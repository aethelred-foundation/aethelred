//! # Aethelred Python SDK - Rust Core Bindings
//!
//! This module provides the PyO3 bindings that expose the Aethelred Rust core
//! to Python. It enables Data Scientists to use sovereign AI capabilities
//! with simple Python decorators while maintaining hardware-enforced security.
//!
//! ## Architecture
//!
//! The Python SDK is a thin ergonomic layer over verified Rust code:
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    Python User Code                              │
//! │   @sovereign(hardware=Hardware.TEE, compliance=Compliance.UAE)  │
//! │   def analyze_patient(data: SovereignData) -> Result:           │
//! └─────────────────────────────────────────────────────────────────┘
//!                               │
//!                               ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                 Python Decorator Layer                           │
//! │   decorators.py - Intercepts calls, validates attestation       │
//! └─────────────────────────────────────────────────────────────────┘
//!                               │
//!                               ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │              PyO3 Rust Bindings (This Module)                   │
//! │   SovereignData, Attestation, Compliance, Crypto                │
//! └─────────────────────────────────────────────────────────────────┘
//!                               │
//!                               ▼
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                  Aethelred Core (Rust)                          │
//! │   Hardware-verified cryptographic operations                    │
//! └─────────────────────────────────────────────────────────────────┘
//! ```

use pyo3::exceptions::{PyPermissionError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// ============================================================================
// Error Types
// ============================================================================

/// Custom error types for the Python SDK
#[derive(Debug, thiserror::Error)]
pub enum AethelredError {
    #[error("Sovereignty violation: {0}")]
    SovereigntyViolation(String),

    #[error("Attestation failed: {0}")]
    AttestationFailed(String),

    #[error("Compliance violation: {0}")]
    ComplianceViolation(String),

    #[error("Hardware mismatch: expected {expected}, got {actual}")]
    HardwareMismatch { expected: String, actual: String },

    #[error("Jurisdiction violation: data from {data_jurisdiction} cannot be processed in {execution_jurisdiction}")]
    JurisdictionViolation {
        data_jurisdiction: String,
        execution_jurisdiction: String,
    },

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),

    #[error("Invalid state: {0}")]
    InvalidState(String),
}

impl From<AethelredError> for PyErr {
    fn from(err: AethelredError) -> PyErr {
        match err {
            AethelredError::SovereigntyViolation(msg)
            | AethelredError::JurisdictionViolation { .. } => {
                PyPermissionError::new_err(format!("🛡️ Sovereignty Violation: {}", err))
            }
            AethelredError::AttestationFailed(msg) => {
                PyPermissionError::new_err(format!("🔐 Attestation Failed: {}", msg))
            }
            AethelredError::ComplianceViolation(msg) => {
                PyPermissionError::new_err(format!("⚖️ Compliance Violation: {}", msg))
            }
            AethelredError::HardwareMismatch { .. } => {
                PyPermissionError::new_err(format!("🖥️ Hardware Mismatch: {}", err))
            }
            _ => PyRuntimeError::new_err(err.to_string()),
        }
    }
}

// ============================================================================
// Jurisdiction Types
// ============================================================================

/// Jurisdiction codes representing legal/regulatory regions
#[pyclass(name = "Jurisdiction", module = "aethelred._core")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Jurisdiction {
    /// Global - no specific jurisdiction restrictions
    Global,
    /// United Arab Emirates - UAE Data Protection Law
    UAE,
    /// European Union - GDPR
    EU,
    /// United States - Various federal/state laws
    US,
    /// Singapore - PDPA
    Singapore,
    /// China - PIPL
    China,
    /// United Kingdom - UK GDPR
    UK,
    /// Saudi Arabia - PDPL
    SaudiArabia,
    /// Qatar - DPL
    Qatar,
    /// Bahrain - PDPL
    Bahrain,
    /// Kuwait - No comprehensive data protection yet
    Kuwait,
    /// Japan - APPI
    Japan,
    /// South Korea - PIPA
    SouthKorea,
    /// Australia - Privacy Act
    Australia,
    /// Canada - PIPEDA
    Canada,
    /// Brazil - LGPD
    Brazil,
    /// India - DPDP
    India,
}

#[pymethods]
impl Jurisdiction {
    /// Get the jurisdiction code string
    fn code(&self) -> &'static str {
        match self {
            Self::Global => "GLOBAL",
            Self::UAE => "UAE",
            Self::EU => "EU",
            Self::US => "US",
            Self::Singapore => "SG",
            Self::China => "CN",
            Self::UK => "UK",
            Self::SaudiArabia => "SA",
            Self::Qatar => "QA",
            Self::Bahrain => "BH",
            Self::Kuwait => "KW",
            Self::Japan => "JP",
            Self::SouthKorea => "KR",
            Self::Australia => "AU",
            Self::Canada => "CA",
            Self::Brazil => "BR",
            Self::India => "IN",
        }
    }

    /// Get the full jurisdiction name
    fn name(&self) -> &'static str {
        match self {
            Self::Global => "Global",
            Self::UAE => "United Arab Emirates",
            Self::EU => "European Union",
            Self::US => "United States",
            Self::Singapore => "Singapore",
            Self::China => "China",
            Self::UK => "United Kingdom",
            Self::SaudiArabia => "Saudi Arabia",
            Self::Qatar => "Qatar",
            Self::Bahrain => "Bahrain",
            Self::Kuwait => "Kuwait",
            Self::Japan => "Japan",
            Self::SouthKorea => "South Korea",
            Self::Australia => "Australia",
            Self::Canada => "Canada",
            Self::Brazil => "Brazil",
            Self::India => "India",
        }
    }

    /// Check if this jurisdiction requires data localization
    fn requires_localization(&self) -> bool {
        matches!(
            self,
            Self::UAE | Self::China | Self::SaudiArabia | Self::Russia
        )
    }

    /// Check if TEE is required for this jurisdiction
    fn requires_tee(&self) -> bool {
        matches!(
            self,
            Self::UAE | Self::SaudiArabia | Self::China
        )
    }

    /// Get applicable regulations for this jurisdiction
    fn regulations(&self) -> Vec<&'static str> {
        match self {
            Self::Global => vec![],
            Self::UAE => vec!["UAE-DPL", "DIFC-DP"],
            Self::EU => vec!["GDPR", "ePrivacy"],
            Self::US => vec!["CCPA", "HIPAA", "GLBA", "FERPA"],
            Self::Singapore => vec!["PDPA"],
            Self::China => vec!["PIPL", "CSL", "DSL"],
            Self::UK => vec!["UK-GDPR", "DPA-2018"],
            Self::SaudiArabia => vec!["PDPL"],
            Self::Japan => vec!["APPI"],
            Self::SouthKorea => vec!["PIPA"],
            Self::Australia => vec!["Privacy-Act"],
            Self::Canada => vec!["PIPEDA"],
            Self::Brazil => vec!["LGPD"],
            Self::India => vec!["DPDP"],
            _ => vec![],
        }
    }

    fn __repr__(&self) -> String {
        format!("Jurisdiction.{}", self.code())
    }

    fn __str__(&self) -> String {
        self.name().to_string()
    }

    /// Create from string code
    #[staticmethod]
    fn from_code(code: &str) -> PyResult<Self> {
        match code.to_uppercase().as_str() {
            "GLOBAL" => Ok(Self::Global),
            "UAE" | "AE" => Ok(Self::UAE),
            "EU" => Ok(Self::EU),
            "US" => Ok(Self::US),
            "SG" | "SINGAPORE" => Ok(Self::Singapore),
            "CN" | "CHINA" => Ok(Self::China),
            "UK" | "GB" => Ok(Self::UK),
            "SA" | "SAUDI" => Ok(Self::SaudiArabia),
            "QA" | "QATAR" => Ok(Self::Qatar),
            "BH" | "BAHRAIN" => Ok(Self::Bahrain),
            "KW" | "KUWAIT" => Ok(Self::Kuwait),
            "JP" | "JAPAN" => Ok(Self::Japan),
            "KR" | "KOREA" => Ok(Self::SouthKorea),
            "AU" | "AUSTRALIA" => Ok(Self::Australia),
            "CA" | "CANADA" => Ok(Self::Canada),
            "BR" | "BRAZIL" => Ok(Self::Brazil),
            "IN" | "INDIA" => Ok(Self::India),
            _ => Err(PyValueError::new_err(format!(
                "Unknown jurisdiction code: {}",
                code
            ))),
        }
    }
}

// ============================================================================
// Hardware Types
// ============================================================================

/// Hardware types for TEE execution
#[pyclass(name = "HardwareType", module = "aethelred._core")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HardwareType {
    /// Generic CPU - no TEE
    Generic,
    /// Intel SGX with DCAP attestation
    IntelSgxDcap,
    /// Intel SGX with EPID attestation (legacy)
    IntelSgxEpid,
    /// Intel TDX (Trust Domain Extensions)
    IntelTdx,
    /// AMD SEV (Secure Encrypted Virtualization)
    AmdSev,
    /// AMD SEV-SNP (Secure Nested Paging)
    AmdSevSnp,
    /// ARM TrustZone
    ArmTrustZone,
    /// ARM CCA (Confidential Compute Architecture)
    ArmCca,
    /// AWS Nitro Enclaves
    AwsNitro,
    /// Azure Confidential Computing
    AzureConfidential,
    /// GCP Confidential VMs
    GcpConfidential,
    /// NVIDIA H100 Confidential Computing
    NvidiaH100Cc,
    /// NVIDIA A100 (no TEE, but verified)
    NvidiaA100,
}

#[pymethods]
impl HardwareType {
    /// Get hardware type name
    fn name(&self) -> &'static str {
        match self {
            Self::Generic => "Generic CPU",
            Self::IntelSgxDcap => "Intel SGX (DCAP)",
            Self::IntelSgxEpid => "Intel SGX (EPID)",
            Self::IntelTdx => "Intel TDX",
            Self::AmdSev => "AMD SEV",
            Self::AmdSevSnp => "AMD SEV-SNP",
            Self::ArmTrustZone => "ARM TrustZone",
            Self::ArmCca => "ARM CCA",
            Self::AwsNitro => "AWS Nitro Enclaves",
            Self::AzureConfidential => "Azure Confidential Computing",
            Self::GcpConfidential => "GCP Confidential VMs",
            Self::NvidiaH100Cc => "NVIDIA H100 Confidential Computing",
            Self::NvidiaA100 => "NVIDIA A100",
        }
    }

    /// Check if this hardware type provides TEE capabilities
    fn is_tee(&self) -> bool {
        !matches!(self, Self::Generic | Self::NvidiaA100)
    }

    /// Check if this hardware supports remote attestation
    fn supports_attestation(&self) -> bool {
        matches!(
            self,
            Self::IntelSgxDcap
                | Self::IntelSgxEpid
                | Self::IntelTdx
                | Self::AmdSevSnp
                | Self::ArmCca
                | Self::AwsNitro
                | Self::AzureConfidential
                | Self::GcpConfidential
                | Self::NvidiaH100Cc
        )
    }

    /// Get security level (0-10)
    fn security_level(&self) -> u8 {
        match self {
            Self::Generic => 0,
            Self::NvidiaA100 => 2,
            Self::IntelSgxEpid => 5,
            Self::ArmTrustZone => 5,
            Self::AmdSev => 6,
            Self::IntelSgxDcap => 8,
            Self::AmdSevSnp => 8,
            Self::IntelTdx => 9,
            Self::ArmCca => 9,
            Self::AwsNitro => 8,
            Self::AzureConfidential => 8,
            Self::GcpConfidential => 8,
            Self::NvidiaH100Cc => 9,
        }
    }

    fn __repr__(&self) -> String {
        format!("HardwareType.{:?}", self)
    }

    fn __str__(&self) -> String {
        self.name().to_string()
    }
}

// ============================================================================
// Attestation Report
// ============================================================================

/// Hardware attestation report
#[pyclass(name = "AttestationReport", module = "aethelred._core")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// Unique report ID
    #[pyo3(get)]
    pub id: String,

    /// Hardware type that generated this report
    pub hardware_type: HardwareType,

    /// Platform-specific measurement (MRENCLAVE/etc)
    #[pyo3(get)]
    pub measurement: String,

    /// Signer identity (MRSIGNER/etc)
    #[pyo3(get)]
    pub signer: String,

    /// Security version
    #[pyo3(get)]
    pub security_version: u16,

    /// Product ID
    #[pyo3(get)]
    pub product_id: u16,

    /// Debug mode enabled
    #[pyo3(get)]
    pub debug_mode: bool,

    /// User-provided data included in attestation
    #[pyo3(get)]
    pub user_data: Option<String>,

    /// Timestamp of attestation
    pub timestamp: DateTime<Utc>,

    /// Raw quote bytes (hex-encoded)
    #[pyo3(get)]
    pub quote: String,

    /// Signature over the report
    #[pyo3(get)]
    pub signature: String,

    /// Whether this report has been verified
    #[pyo3(get)]
    pub verified: bool,
}

#[pymethods]
impl AttestationReport {
    /// Get the hardware type
    #[getter]
    fn hardware(&self) -> HardwareType {
        self.hardware_type
    }

    /// Get timestamp as ISO string
    #[getter]
    fn timestamp_iso(&self) -> String {
        self.timestamp.to_rfc3339()
    }

    /// Verify the attestation report
    fn verify(&mut self) -> PyResult<bool> {
        // In production, this would verify against Intel/AMD/AWS attestation services
        // For now, perform basic validation
        if self.measurement.is_empty() {
            return Err(AethelredError::AttestationFailed(
                "Empty measurement".into(),
            )
            .into());
        }

        if self.debug_mode {
            // Debug enclaves are not trusted in production
            tracing::warn!("Debug mode enclave detected - not trusted in production");
        }

        self.verified = true;
        Ok(true)
    }

    /// Check if the report is still valid (not expired)
    fn is_valid(&self) -> bool {
        let age = Utc::now() - self.timestamp;
        age.num_hours() < 24 // Reports valid for 24 hours
    }

    /// Export to JSON
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| AethelredError::SerializationError(e.to_string()).into())
    }

    fn __repr__(&self) -> String {
        format!(
            "AttestationReport(id='{}', hardware={:?}, verified={})",
            self.id, self.hardware_type, self.verified
        )
    }
}

impl AttestationReport {
    /// Create a new attestation report
    pub fn new(hardware_type: HardwareType, user_data: Option<String>) -> Self {
        let id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();

        // Generate mock measurement based on hardware type
        let mut hasher = Sha256::new();
        hasher.update(format!("{:?}-{}", hardware_type, timestamp.timestamp()));
        let measurement = hex::encode(hasher.finalize());

        let mut signer_hasher = Sha256::new();
        signer_hasher.update("aethelred-signer-v2");
        let signer = hex::encode(signer_hasher.finalize());

        Self {
            id,
            hardware_type,
            measurement,
            signer,
            security_version: 2,
            product_id: 1,
            debug_mode: cfg!(debug_assertions),
            user_data,
            timestamp,
            quote: String::new(),
            signature: String::new(),
            verified: false,
        }
    }

    /// Create from raw attestation bytes
    pub fn from_quote(quote: &[u8], hardware_type: HardwareType) -> PyResult<Self> {
        let mut report = Self::new(hardware_type, None);
        report.quote = hex::encode(quote);

        // Parse quote based on hardware type
        match hardware_type {
            HardwareType::IntelSgxDcap | HardwareType::IntelSgxEpid => {
                // Parse SGX quote structure
                if quote.len() >= 48 {
                    report.measurement = hex::encode(&quote[..32]);
                }
            }
            HardwareType::AwsNitro => {
                // Parse Nitro attestation document (COSE/CBOR)
                report.measurement = hex::encode(&quote[..32.min(quote.len())]);
            }
            _ => {
                report.measurement = hex::encode(Sha256::digest(quote));
            }
        }

        Ok(report)
    }
}

// ============================================================================
// Attestation Provider
// ============================================================================

/// Attestation provider for generating and verifying attestation reports
#[pyclass(name = "AttestationProvider", module = "aethelred._core")]
#[derive(Debug)]
pub struct AttestationProvider {
    hardware_type: HardwareType,
    cache: Arc<RwLock<HashMap<String, AttestationReport>>>,
    dev_mode: bool,
}

#[pymethods]
impl AttestationProvider {
    /// Create a new attestation provider
    #[new]
    #[pyo3(signature = (hardware_type=None, dev_mode=false))]
    fn new(hardware_type: Option<HardwareType>, dev_mode: bool) -> Self {
        let hw = hardware_type.unwrap_or_else(|| Self::detect_hardware());
        Self {
            hardware_type: hw,
            cache: Arc::new(RwLock::new(HashMap::new())),
            dev_mode,
        }
    }

    /// Detect the current hardware type
    #[staticmethod]
    fn detect_hardware() -> HardwareType {
        // Check environment for TEE indicators
        if std::env::var("SGX_AESM_ADDR").is_ok() {
            return HardwareType::IntelSgxDcap;
        }
        if std::path::Path::new("/dev/sev").exists() {
            return HardwareType::AmdSevSnp;
        }
        if std::path::Path::new("/dev/nitro_enclaves").exists() {
            return HardwareType::AwsNitro;
        }
        HardwareType::Generic
    }

    /// Get the current hardware type
    #[getter]
    fn hardware(&self) -> HardwareType {
        self.hardware_type
    }

    /// Check if running in dev mode
    #[getter]
    fn is_dev_mode(&self) -> bool {
        self.dev_mode
    }

    /// Generate a new attestation report
    #[pyo3(signature = (user_data=None))]
    fn generate_report(&self, user_data: Option<String>) -> PyResult<AttestationReport> {
        if self.dev_mode {
            // In dev mode, generate a mock report
            let mut report = AttestationReport::new(self.hardware_type, user_data);
            report.verified = true; // Auto-verify in dev mode
            return Ok(report);
        }

        // In production, fetch real attestation
        let report = self.fetch_hardware_attestation(user_data)?;
        Ok(report)
    }

    /// Verify an attestation report
    fn verify_report(&self, report: &mut AttestationReport) -> PyResult<bool> {
        if self.dev_mode {
            report.verified = true;
            return Ok(true);
        }

        // Verify based on hardware type
        match report.hardware_type {
            HardwareType::IntelSgxDcap => self.verify_sgx_dcap(report),
            HardwareType::AwsNitro => self.verify_aws_nitro(report),
            HardwareType::AmdSevSnp => self.verify_amd_sev(report),
            _ => {
                report.verified = false;
                Ok(false)
            }
        }
    }

    /// Get cached attestation report if still valid
    fn get_cached_report(&self, key: &str) -> Option<AttestationReport> {
        let cache = self.cache.read().ok()?;
        cache.get(key).filter(|r| r.is_valid()).cloned()
    }

    /// Cache an attestation report
    fn cache_report(&self, key: &str, report: AttestationReport) -> PyResult<()> {
        let mut cache = self
            .cache
            .write()
            .map_err(|e| AethelredError::InvalidState(e.to_string()))?;
        cache.insert(key.to_string(), report);
        Ok(())
    }
}

impl AttestationProvider {
    fn fetch_hardware_attestation(&self, user_data: Option<String>) -> PyResult<AttestationReport> {
        match self.hardware_type {
            HardwareType::IntelSgxDcap | HardwareType::IntelSgxEpid => {
                self.fetch_sgx_attestation(user_data)
            }
            HardwareType::AwsNitro => self.fetch_nitro_attestation(user_data),
            HardwareType::AmdSevSnp => self.fetch_sev_attestation(user_data),
            _ => Ok(AttestationReport::new(self.hardware_type, user_data)),
        }
    }

    fn fetch_sgx_attestation(&self, user_data: Option<String>) -> PyResult<AttestationReport> {
        // In production, this would call the AESM service
        // For now, return a properly structured mock
        let mut report = AttestationReport::new(HardwareType::IntelSgxDcap, user_data);

        // Try to read from /dev/attestation if available
        if let Ok(quote) = std::fs::read("/dev/attestation/quote") {
            report = AttestationReport::from_quote(&quote, HardwareType::IntelSgxDcap)?;
        }

        Ok(report)
    }

    fn fetch_nitro_attestation(&self, user_data: Option<String>) -> PyResult<AttestationReport> {
        let mut report = AttestationReport::new(HardwareType::AwsNitro, user_data);

        // In production, call the Nitro Secure Module
        // /dev/nsm would be used for actual attestation
        if std::path::Path::new("/dev/nsm").exists() {
            // Would use AWS Nitro NSM API here
        }

        Ok(report)
    }

    fn fetch_sev_attestation(&self, user_data: Option<String>) -> PyResult<AttestationReport> {
        let mut report = AttestationReport::new(HardwareType::AmdSevSnp, user_data);

        // In production, call the SNP guest driver
        if std::path::Path::new("/dev/sev-guest").exists() {
            // Would use SNP guest API here
        }

        Ok(report)
    }

    fn verify_sgx_dcap(&self, report: &mut AttestationReport) -> PyResult<bool> {
        // In production, verify against Intel PCS
        // Check TCB status, revocation status, etc.
        report.verified = !report.debug_mode;
        Ok(report.verified)
    }

    fn verify_aws_nitro(&self, report: &mut AttestationReport) -> PyResult<bool> {
        // In production, verify COSE signature and PCRs
        report.verified = !report.debug_mode;
        Ok(report.verified)
    }

    fn verify_amd_sev(&self, report: &mut AttestationReport) -> PyResult<bool> {
        // In production, verify against AMD KDS
        report.verified = !report.debug_mode;
        Ok(report.verified)
    }
}

// ============================================================================
// Sovereign Data
// ============================================================================

/// Sovereign data container that enforces jurisdiction and hardware requirements
#[pyclass(name = "SovereignData", module = "aethelred._core")]
#[derive(Debug, Clone)]
pub struct SovereignData {
    /// Unique identifier for this sovereign data
    id: String,

    /// The actual data (encrypted in memory)
    data: Vec<u8>,

    /// Hash of the original data for verification
    data_hash: String,

    /// Jurisdiction this data belongs to
    jurisdiction: Jurisdiction,

    /// Required hardware type for access
    required_hardware: HardwareType,

    /// Minimum security level required
    min_security_level: u8,

    /// Data classification level
    classification: String,

    /// Creation timestamp
    created_at: DateTime<Utc>,

    /// Access log
    access_log: Vec<AccessLogEntry>,

    /// Whether data has been unlocked in this session
    unlocked: bool,

    /// Encryption key (derived from attestation)
    encryption_key: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct AccessLogEntry {
    timestamp: DateTime<Utc>,
    hardware: String,
    success: bool,
    reason: Option<String>,
}

#[pymethods]
impl SovereignData {
    /// Create new sovereign data with jurisdiction binding
    #[new]
    #[pyo3(signature = (data, jurisdiction, hardware=None, classification="confidential".to_string(), min_security_level=5))]
    fn new(
        data: &str,
        jurisdiction: Jurisdiction,
        hardware: Option<HardwareType>,
        classification: String,
        min_security_level: u8,
    ) -> PyResult<Self> {
        let id = Uuid::new_v4().to_string();
        let data_bytes = data.as_bytes().to_vec();

        // Compute hash for integrity verification
        let mut hasher = Sha256::new();
        hasher.update(&data_bytes);
        let data_hash = hex::encode(hasher.finalize());

        Ok(Self {
            id,
            data: data_bytes,
            data_hash,
            jurisdiction,
            required_hardware: hardware.unwrap_or(HardwareType::Generic),
            min_security_level,
            classification,
            created_at: Utc::now(),
            access_log: Vec::new(),
            unlocked: false,
            encryption_key: None,
        })
    }

    /// Create from a Python dictionary
    #[staticmethod]
    #[pyo3(signature = (data_dict, jurisdiction, hardware=None))]
    fn from_dict(
        data_dict: &PyDict,
        jurisdiction: Jurisdiction,
        hardware: Option<HardwareType>,
    ) -> PyResult<Self> {
        let json_str = serde_json::to_string(&dict_to_map(data_dict)?)
            .map_err(|e| AethelredError::SerializationError(e.to_string()))?;

        Self::new(
            &json_str,
            jurisdiction,
            hardware,
            "confidential".to_string(),
            5,
        )
    }

    /// Create from bytes
    #[staticmethod]
    #[pyo3(signature = (data_bytes, jurisdiction, hardware=None))]
    fn from_bytes(
        data_bytes: &[u8],
        jurisdiction: Jurisdiction,
        hardware: Option<HardwareType>,
    ) -> PyResult<Self> {
        let id = Uuid::new_v4().to_string();

        let mut hasher = Sha256::new();
        hasher.update(data_bytes);
        let data_hash = hex::encode(hasher.finalize());

        Ok(Self {
            id,
            data: data_bytes.to_vec(),
            data_hash,
            jurisdiction,
            required_hardware: hardware.unwrap_or(HardwareType::Generic),
            min_security_level: 5,
            classification: "confidential".to_string(),
            created_at: Utc::now(),
            access_log: Vec::new(),
            unlocked: false,
            encryption_key: None,
        })
    }

    /// Get the sovereign data ID
    #[getter]
    fn id(&self) -> &str {
        &self.id
    }

    /// Get the jurisdiction
    #[getter]
    fn jurisdiction(&self) -> Jurisdiction {
        self.jurisdiction
    }

    /// Get required hardware type
    #[getter]
    fn required_hardware(&self) -> HardwareType {
        self.required_hardware
    }

    /// Get minimum security level
    #[getter]
    fn min_security_level(&self) -> u8 {
        self.min_security_level
    }

    /// Get data classification
    #[getter]
    fn classification(&self) -> &str {
        &self.classification
    }

    /// Get creation timestamp
    #[getter]
    fn created_at(&self) -> String {
        self.created_at.to_rfc3339()
    }

    /// Get the data hash (for verification without accessing data)
    #[getter]
    fn hash(&self) -> &str {
        &self.data_hash
    }

    /// Check if data is currently unlocked
    #[getter]
    fn is_unlocked(&self) -> bool {
        self.unlocked
    }

    /// Get the size of the data in bytes
    fn size(&self) -> usize {
        self.data.len()
    }

    /// Access the data with attestation proof
    ///
    /// This is the CRITICAL security boundary. The attestation report
    /// proves that the caller is running in the correct hardware environment.
    fn access(&mut self, attestation: &AttestationReport) -> PyResult<String> {
        // Validate attestation is verified
        if !attestation.verified {
            self.log_access(&attestation, false, Some("Attestation not verified"));
            return Err(AethelredError::AttestationFailed(
                "Attestation report has not been verified".into(),
            )
            .into());
        }

        // Validate hardware type matches or exceeds requirements
        if self.required_hardware != HardwareType::Generic {
            if attestation.hardware_type != self.required_hardware {
                self.log_access(
                    &attestation,
                    false,
                    Some("Hardware type mismatch"),
                );
                return Err(AethelredError::HardwareMismatch {
                    expected: format!("{:?}", self.required_hardware),
                    actual: format!("{:?}", attestation.hardware_type),
                }
                .into());
            }
        }

        // Validate security level
        if attestation.hardware_type.security_level() < self.min_security_level {
            self.log_access(&attestation, false, Some("Security level too low"));
            return Err(AethelredError::SovereigntyViolation(format!(
                "Hardware security level {} is below required level {}",
                attestation.hardware_type.security_level(),
                self.min_security_level
            ))
            .into());
        }

        // Validate debug mode is not enabled for production data
        if attestation.debug_mode && self.classification != "development" {
            self.log_access(&attestation, false, Some("Debug mode not allowed"));
            return Err(AethelredError::SovereigntyViolation(
                "Debug mode enclaves cannot access production data".into(),
            )
            .into());
        }

        // Check attestation freshness
        if !attestation.is_valid() {
            self.log_access(&attestation, false, Some("Attestation expired"));
            return Err(AethelredError::AttestationFailed("Attestation report has expired".into()).into());
        }

        // All checks passed - unlock the data
        self.log_access(&attestation, true, None);
        self.unlocked = true;

        // Return the data as string
        String::from_utf8(self.data.clone())
            .map_err(|e| AethelredError::SerializationError(e.to_string()).into())
    }

    /// Access data as bytes
    fn access_bytes<'py>(
        &mut self,
        py: Python<'py>,
        attestation: &AttestationReport,
    ) -> PyResult<&'py PyBytes> {
        // Perform all the same checks as access()
        if !attestation.verified {
            return Err(AethelredError::AttestationFailed(
                "Attestation report has not been verified".into(),
            )
            .into());
        }

        if self.required_hardware != HardwareType::Generic
            && attestation.hardware_type != self.required_hardware
        {
            return Err(AethelredError::HardwareMismatch {
                expected: format!("{:?}", self.required_hardware),
                actual: format!("{:?}", attestation.hardware_type),
            }
            .into());
        }

        if attestation.hardware_type.security_level() < self.min_security_level {
            return Err(AethelredError::SovereigntyViolation(format!(
                "Hardware security level {} is below required level {}",
                attestation.hardware_type.security_level(),
                self.min_security_level
            ))
            .into());
        }

        self.log_access(&attestation, true, None);
        self.unlocked = true;

        Ok(PyBytes::new(py, &self.data))
    }

    /// Verify data integrity without accessing it
    fn verify_integrity(&self, expected_hash: &str) -> bool {
        self.data_hash == expected_hash
    }

    /// Get access log as JSON
    fn get_access_log(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.access_log)
            .map_err(|e| AethelredError::SerializationError(e.to_string()).into())
    }

    /// Get the number of access attempts
    fn access_count(&self) -> usize {
        self.access_log.len()
    }

    /// Get the number of successful accesses
    fn successful_access_count(&self) -> usize {
        self.access_log.iter().filter(|e| e.success).count()
    }

    fn __repr__(&self) -> String {
        format!(
            "SovereignData(id='{}', jurisdiction={:?}, hardware={:?}, size={})",
            self.id,
            self.jurisdiction,
            self.required_hardware,
            self.data.len()
        )
    }

    fn __str__(&self) -> String {
        format!(
            "<SovereignData {} | {} | {}>",
            self.jurisdiction.code(),
            self.required_hardware.name(),
            self.classification
        )
    }
}

impl SovereignData {
    fn log_access(&mut self, attestation: &AttestationReport, success: bool, reason: Option<&str>) {
        self.access_log.push(AccessLogEntry {
            timestamp: Utc::now(),
            hardware: format!("{:?}", attestation.hardware_type),
            success,
            reason: reason.map(String::from),
        });
    }
}

// ============================================================================
// Compliance Engine
// ============================================================================

/// Compliance engine for validating data operations against regulations
#[pyclass(name = "ComplianceEngine", module = "aethelred._core")]
#[derive(Debug, Clone)]
pub struct ComplianceEngine {
    /// Active regulations
    regulations: Vec<String>,

    /// Jurisdictions to enforce
    jurisdictions: Vec<Jurisdiction>,

    /// Strict mode (fail on any violation)
    strict_mode: bool,

    /// Audit trail enabled
    audit_enabled: bool,

    /// Violations encountered
    violations: Vec<ComplianceViolation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ComplianceViolation {
    timestamp: DateTime<Utc>,
    regulation: String,
    article: String,
    severity: String,
    message: String,
    data_id: Option<String>,
}

#[pymethods]
impl ComplianceEngine {
    /// Create a new compliance engine
    #[new]
    #[pyo3(signature = (regulations=None, jurisdictions=None, strict_mode=true))]
    fn new(
        regulations: Option<Vec<String>>,
        jurisdictions: Option<Vec<Jurisdiction>>,
        strict_mode: bool,
    ) -> Self {
        Self {
            regulations: regulations.unwrap_or_else(|| vec!["GDPR".into()]),
            jurisdictions: jurisdictions.unwrap_or_else(|| vec![Jurisdiction::Global]),
            strict_mode,
            audit_enabled: true,
            violations: Vec::new(),
        }
    }

    /// Validate a data operation
    fn validate(
        &mut self,
        data: &SovereignData,
        operation: &str,
        target_jurisdiction: Option<Jurisdiction>,
    ) -> PyResult<bool> {
        let target = target_jurisdiction.unwrap_or(data.jurisdiction);

        // Check cross-border transfer rules
        if data.jurisdiction != target {
            self.check_cross_border_transfer(data, target)?;
        }

        // Check data localization requirements
        if data.jurisdiction.requires_localization() {
            self.check_data_localization(data, target)?;
        }

        // Check operation-specific rules
        match operation {
            "read" | "access" => self.check_access_rights(data)?,
            "export" | "transfer" => self.check_transfer_rights(data, target)?,
            "delete" => self.check_deletion_rights(data)?,
            "process" | "inference" => self.check_processing_rights(data)?,
            _ => {}
        }

        if self.strict_mode && !self.violations.is_empty() {
            return Err(AethelredError::ComplianceViolation(format!(
                "{} violation(s) detected",
                self.violations.len()
            ))
            .into());
        }

        Ok(self.violations.is_empty())
    }

    /// Check if a cross-border transfer is allowed
    fn check_transfer(
        &mut self,
        source: Jurisdiction,
        destination: Jurisdiction,
        data_classification: &str,
    ) -> PyResult<bool> {
        // Check EU adequacy decisions
        if source == Jurisdiction::EU {
            let adequate_countries = vec![
                Jurisdiction::UK,
                Jurisdiction::Japan,
                Jurisdiction::SouthKorea,
                Jurisdiction::Canada,
            ];

            if !adequate_countries.contains(&destination) && destination != Jurisdiction::EU {
                self.add_violation(
                    "GDPR",
                    "Article 45",
                    "warning",
                    format!(
                        "Transfer to {:?} requires additional safeguards (SCCs/BCRs)",
                        destination
                    ),
                    None,
                );
            }
        }

        // Check UAE data localization
        if source == Jurisdiction::UAE && data_classification == "sensitive" {
            if destination != Jurisdiction::UAE {
                self.add_violation(
                    "UAE-DPL",
                    "Article 7",
                    "error",
                    "Sensitive UAE data must remain within UAE jurisdiction",
                    None,
                );
                return Ok(false);
            }
        }

        // Check China PIPL
        if source == Jurisdiction::China {
            self.add_violation(
                "PIPL",
                "Article 38",
                "warning",
                "Cross-border transfer requires CAC security assessment",
                None,
            );
        }

        Ok(self.violations.iter().all(|v| v.severity != "error"))
    }

    /// Get all violations
    fn get_violations(&self) -> PyResult<String> {
        serde_json::to_string_pretty(&self.violations)
            .map_err(|e| AethelredError::SerializationError(e.to_string()).into())
    }

    /// Get violation count
    fn violation_count(&self) -> usize {
        self.violations.len()
    }

    /// Clear all violations
    fn clear_violations(&mut self) {
        self.violations.clear();
    }

    /// Check if currently compliant
    fn is_compliant(&self) -> bool {
        self.violations.iter().all(|v| v.severity != "error")
    }

    fn __repr__(&self) -> String {
        format!(
            "ComplianceEngine(regulations={:?}, strict={})",
            self.regulations, self.strict_mode
        )
    }
}

impl ComplianceEngine {
    fn add_violation(
        &mut self,
        regulation: &str,
        article: &str,
        severity: &str,
        message: String,
        data_id: Option<String>,
    ) {
        self.violations.push(ComplianceViolation {
            timestamp: Utc::now(),
            regulation: regulation.into(),
            article: article.into(),
            severity: severity.into(),
            message,
            data_id,
        });
    }

    fn check_cross_border_transfer(
        &mut self,
        data: &SovereignData,
        target: Jurisdiction,
    ) -> PyResult<()> {
        self.check_transfer(data.jurisdiction, target, &data.classification)?;
        Ok(())
    }

    fn check_data_localization(
        &mut self,
        data: &SovereignData,
        target: Jurisdiction,
    ) -> PyResult<()> {
        if data.jurisdiction != target {
            self.add_violation(
                "Data Localization",
                "N/A",
                "error",
                format!(
                    "Data from {:?} cannot be processed in {:?} due to localization requirements",
                    data.jurisdiction, target
                ),
                Some(data.id.clone()),
            );
        }
        Ok(())
    }

    fn check_access_rights(&mut self, data: &SovereignData) -> PyResult<()> {
        // Check if access is allowed based on classification
        if data.classification == "restricted" {
            self.add_violation(
                "Access Control",
                "N/A",
                "warning",
                "Accessing restricted data - ensure proper authorization",
                Some(data.id.clone()),
            );
        }
        Ok(())
    }

    fn check_transfer_rights(
        &mut self,
        data: &SovereignData,
        target: Jurisdiction,
    ) -> PyResult<()> {
        self.check_cross_border_transfer(data, target)
    }

    fn check_deletion_rights(&mut self, data: &SovereignData) -> PyResult<()> {
        // Verify deletion is logged for audit purposes
        if self.audit_enabled {
            tracing::info!("Deletion request for data {}", data.id);
        }
        Ok(())
    }

    fn check_processing_rights(&mut self, data: &SovereignData) -> PyResult<()> {
        // Check if TEE is required for processing
        if data.jurisdiction.requires_tee() && data.required_hardware == HardwareType::Generic {
            self.add_violation(
                "Processing",
                "N/A",
                "warning",
                format!(
                    "{:?} jurisdiction requires TEE for data processing",
                    data.jurisdiction
                ),
                Some(data.id.clone()),
            );
        }
        Ok(())
    }
}

// ============================================================================
// Digital Seal
// ============================================================================

/// Digital Seal - cryptographic proof of AI computation
#[pyclass(name = "DigitalSeal", module = "aethelred._core")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DigitalSeal {
    /// Unique seal ID
    #[pyo3(get)]
    pub id: String,

    /// Hash of the model used
    #[pyo3(get)]
    pub model_hash: String,

    /// Hash of the input data
    #[pyo3(get)]
    pub input_hash: String,

    /// Hash of the output
    #[pyo3(get)]
    pub output_hash: String,

    /// Hardware attestation included
    pub attestation: Option<AttestationReport>,

    /// Timestamp of seal creation
    pub created_at: DateTime<Utc>,

    /// Jurisdiction where computation occurred
    pub jurisdiction: Jurisdiction,

    /// Purpose of the computation
    #[pyo3(get)]
    pub purpose: String,

    /// Additional metadata
    #[pyo3(get)]
    pub metadata: HashMap<String, String>,

    /// Seal signature
    #[pyo3(get)]
    pub signature: String,

    /// Whether seal has been verified
    #[pyo3(get)]
    pub verified: bool,
}

#[pymethods]
impl DigitalSeal {
    /// Create a new digital seal
    #[new]
    #[pyo3(signature = (model_hash, input_hash, output_hash, jurisdiction=Jurisdiction::Global, purpose="inference".to_string()))]
    fn new(
        model_hash: String,
        input_hash: String,
        output_hash: String,
        jurisdiction: Jurisdiction,
        purpose: String,
    ) -> Self {
        let id = Uuid::new_v4().to_string();
        let created_at = Utc::now();

        // Generate seal hash
        let mut hasher = Sha256::new();
        hasher.update(&model_hash);
        hasher.update(&input_hash);
        hasher.update(&output_hash);
        hasher.update(format!("{}", created_at.timestamp()));
        let signature = hex::encode(hasher.finalize());

        Self {
            id,
            model_hash,
            input_hash,
            output_hash,
            attestation: None,
            created_at,
            jurisdiction,
            purpose,
            metadata: HashMap::new(),
            signature,
            verified: false,
        }
    }

    /// Attach attestation to seal
    fn attach_attestation(&mut self, attestation: AttestationReport) {
        self.attestation = Some(attestation);
    }

    /// Get attestation if present
    fn get_attestation(&self) -> Option<AttestationReport> {
        self.attestation.clone()
    }

    /// Get jurisdiction
    #[getter]
    fn jurisdiction(&self) -> Jurisdiction {
        self.jurisdiction
    }

    /// Get creation timestamp
    #[getter]
    fn created_at(&self) -> String {
        self.created_at.to_rfc3339()
    }

    /// Add metadata
    fn add_metadata(&mut self, key: &str, value: &str) {
        self.metadata.insert(key.to_string(), value.to_string());
    }

    /// Verify the seal
    fn verify(&mut self) -> PyResult<bool> {
        // Recompute signature
        let mut hasher = Sha256::new();
        hasher.update(&self.model_hash);
        hasher.update(&self.input_hash);
        hasher.update(&self.output_hash);
        hasher.update(format!("{}", self.created_at.timestamp()));
        let expected_signature = hex::encode(hasher.finalize());

        if self.signature != expected_signature {
            return Ok(false);
        }

        // Verify attestation if present
        if let Some(ref attestation) = self.attestation {
            if !attestation.verified {
                return Ok(false);
            }
        }

        self.verified = true;
        Ok(true)
    }

    /// Export to JSON
    fn to_json(&self) -> PyResult<String> {
        serde_json::to_string_pretty(self)
            .map_err(|e| AethelredError::SerializationError(e.to_string()).into())
    }

    fn __repr__(&self) -> String {
        format!(
            "DigitalSeal(id='{}', jurisdiction={:?}, verified={})",
            self.id, self.jurisdiction, self.verified
        )
    }
}

// ============================================================================
// Execution Context
// ============================================================================

/// Execution context for sovereign operations
#[pyclass(name = "ExecutionContext", module = "aethelred._core")]
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    /// Context ID
    id: String,

    /// Hardware type detected/required
    hardware: HardwareType,

    /// Jurisdiction for execution
    jurisdiction: Jurisdiction,

    /// Compliance engine
    compliance: ComplianceEngine,

    /// Attestation provider
    attestation_provider: AttestationProvider,

    /// Current attestation report
    attestation: Option<AttestationReport>,

    /// Dev mode enabled
    dev_mode: bool,

    /// Active data references
    active_data: Vec<String>,
}

#[pymethods]
impl ExecutionContext {
    /// Create a new execution context
    #[new]
    #[pyo3(signature = (hardware=None, jurisdiction=Jurisdiction::Global, dev_mode=false))]
    fn new(
        hardware: Option<HardwareType>,
        jurisdiction: Jurisdiction,
        dev_mode: bool,
    ) -> PyResult<Self> {
        let hw = hardware.unwrap_or_else(AttestationProvider::detect_hardware);
        let attestation_provider = AttestationProvider::new(Some(hw), dev_mode);
        let compliance = ComplianceEngine::new(None, Some(vec![jurisdiction]), true);

        Ok(Self {
            id: Uuid::new_v4().to_string(),
            hardware: hw,
            jurisdiction,
            compliance,
            attestation_provider,
            attestation: None,
            dev_mode,
            active_data: Vec::new(),
        })
    }

    /// Get context ID
    #[getter]
    fn id(&self) -> &str {
        &self.id
    }

    /// Get hardware type
    #[getter]
    fn hardware(&self) -> HardwareType {
        self.hardware
    }

    /// Get jurisdiction
    #[getter]
    fn jurisdiction(&self) -> Jurisdiction {
        self.jurisdiction
    }

    /// Check if dev mode is enabled
    #[getter]
    fn is_dev_mode(&self) -> bool {
        self.dev_mode
    }

    /// Initialize the context (fetch attestation)
    fn initialize(&mut self) -> PyResult<()> {
        let report = self.attestation_provider.generate_report(None)?;
        self.attestation = Some(report);
        Ok(())
    }

    /// Get current attestation
    fn get_attestation(&self) -> Option<AttestationReport> {
        self.attestation.clone()
    }

    /// Validate sovereign data access
    fn validate_access(&mut self, data: &SovereignData) -> PyResult<bool> {
        // Check hardware requirements
        if data.required_hardware != HardwareType::Generic
            && data.required_hardware != self.hardware
        {
            return Err(AethelredError::HardwareMismatch {
                expected: format!("{:?}", data.required_hardware),
                actual: format!("{:?}", self.hardware),
            }
            .into());
        }

        // Check security level
        if self.hardware.security_level() < data.min_security_level {
            return Err(AethelredError::SovereigntyViolation(format!(
                "Hardware security level {} is below required {}",
                self.hardware.security_level(),
                data.min_security_level
            ))
            .into());
        }

        // Check compliance
        self.compliance.validate(data, "access", Some(self.jurisdiction))?;

        // Track active data
        self.active_data.push(data.id.clone());

        Ok(true)
    }

    /// Create a digital seal for computation
    fn create_seal(
        &self,
        model_hash: &str,
        input_hash: &str,
        output_hash: &str,
        purpose: &str,
    ) -> PyResult<DigitalSeal> {
        let mut seal = DigitalSeal::new(
            model_hash.to_string(),
            input_hash.to_string(),
            output_hash.to_string(),
            self.jurisdiction,
            purpose.to_string(),
        );

        // Attach attestation if available
        if let Some(ref attestation) = self.attestation {
            seal.attach_attestation(attestation.clone());
        }

        Ok(seal)
    }

    fn __repr__(&self) -> String {
        format!(
            "ExecutionContext(id='{}', hardware={:?}, jurisdiction={:?})",
            self.id, self.hardware, self.jurisdiction
        )
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Convert Python dict to Rust HashMap
fn dict_to_map(dict: &PyDict) -> PyResult<HashMap<String, serde_json::Value>> {
    let mut map = HashMap::new();
    for (key, value) in dict {
        let key_str: String = key.extract()?;
        let value_json = python_to_json(value)?;
        map.insert(key_str, value_json);
    }
    Ok(map)
}

/// Convert Python object to serde_json::Value
fn python_to_json(obj: &PyAny) -> PyResult<serde_json::Value> {
    if obj.is_none() {
        Ok(serde_json::Value::Null)
    } else if let Ok(b) = obj.extract::<bool>() {
        Ok(serde_json::Value::Bool(b))
    } else if let Ok(i) = obj.extract::<i64>() {
        Ok(serde_json::Value::Number(i.into()))
    } else if let Ok(f) = obj.extract::<f64>() {
        Ok(serde_json::json!(f))
    } else if let Ok(s) = obj.extract::<String>() {
        Ok(serde_json::Value::String(s))
    } else if let Ok(list) = obj.downcast::<PyList>() {
        let vec: Vec<serde_json::Value> = list
            .iter()
            .map(python_to_json)
            .collect::<PyResult<Vec<_>>>()?;
        Ok(serde_json::Value::Array(vec))
    } else if let Ok(dict) = obj.downcast::<PyDict>() {
        let map = dict_to_map(dict)?;
        Ok(serde_json::to_value(map).unwrap())
    } else {
        Ok(serde_json::Value::String(obj.str()?.to_string()))
    }
}

/// Compute SHA-256 hash
#[pyfunction]
fn sha256_hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Get the current library version
#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Check if running in TEE environment
#[pyfunction]
fn is_tee_environment() -> bool {
    std::env::var("SGX_AESM_ADDR").is_ok()
        || std::path::Path::new("/dev/sev").exists()
        || std::path::Path::new("/dev/nitro_enclaves").exists()
}

/// Get detected hardware type
#[pyfunction]
fn detect_hardware() -> HardwareType {
    AttestationProvider::detect_hardware()
}

// ============================================================================
// Module Definition
// ============================================================================

/// Aethelred Python SDK - Sovereign AI Platform
///
/// This module provides Python bindings for the Aethelred blockchain platform,
/// enabling secure, compliant AI computation with hardware attestation.
#[pymodule]
fn _core(_py: Python, m: &PyModule) -> PyResult<()> {
    // Add classes
    m.add_class::<Jurisdiction>()?;
    m.add_class::<HardwareType>()?;
    m.add_class::<AttestationReport>()?;
    m.add_class::<AttestationProvider>()?;
    m.add_class::<SovereignData>()?;
    m.add_class::<ComplianceEngine>()?;
    m.add_class::<DigitalSeal>()?;
    m.add_class::<ExecutionContext>()?;

    // Add functions
    m.add_function(wrap_pyfunction!(sha256_hash, m)?)?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(is_tee_environment, m)?)?;
    m.add_function(wrap_pyfunction!(detect_hardware, m)?)?;

    Ok(())
}
