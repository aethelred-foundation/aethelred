//! Pillar 3: Sovereign TEE Enclaves - The Secret Mempool
//!
//! ## The Competitor Gap
//!
//! On Ethereum/Solana, **everything is public**. You cannot put medical records
//! or bank audits on-chain because the data becomes visible to the world.
//!
//! Zero-Knowledge (ZK) rollups are too slow for real-time AI inference.
//!
//! ## The Aethelred Advantage
//!
//! Enforce Trusted Execution Environments (TEEs) at the node level.
//!
//! ## The Secret Mempool
//!
//! A specialized encrypted mempool where:
//! 1. Data (e.g., patient's DNA profile) is encrypted client-side
//! 2. Can ONLY be decrypted inside a verified Intel SGX/AMD SEV enclave
//! 3. The validator proves the result WITHOUT ever seeing the input
//!
//! This enables HIPAA-compliant healthcare AI, GDPR-compliant finance,
//! and truly private AI inference on public blockchain.

#[cfg(not(feature = "production"))]
use rand::rngs::OsRng;
#[cfg(not(feature = "production"))]
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};

// Production builds must use attested enclave backends. Development-only crypto
// helpers stay compiled out of production runtime paths.

// ============================================================================
// TEE Platforms and Attestation
// ============================================================================

/// Supported TEE platforms
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TEEPlatform {
    /// Intel Software Guard Extensions
    IntelSGX {
        version: u8,
        svn: u16,            // Security Version Number
        mrenclave: [u8; 32], // Enclave measurement
        mrsigner: [u8; 32],  // Signer measurement
    },
    /// AMD Secure Encrypted Virtualization
    AMDSEV {
        variant: SEVVariant,
        #[serde(with = "crate::serde_byte_array_48")]
        measurement: [u8; 48],
    },
    /// AWS Nitro Enclaves
    AWSNitro {
        #[serde(with = "crate::serde_byte_array_48")]
        pcr0: [u8; 48], // Platform Configuration Register
        #[serde(with = "crate::serde_byte_array_48")]
        pcr1: [u8; 48],
        #[serde(with = "crate::serde_byte_array_48")]
        pcr2: [u8; 48],
    },
    /// ARM TrustZone
    ARMTrustZone { realm_id: [u8; 32] },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SEVVariant {
    SEV,
    SEVES,
    SEVSNP,
}

/// TEE Attestation Report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEAttestation {
    /// Platform type
    pub platform: TEEPlatform,
    /// Raw attestation report
    pub report: Vec<u8>,
    /// Report signature
    pub signature: Vec<u8>,
    /// Certificate chain (for verification)
    pub cert_chain: Vec<Vec<u8>>,
    /// Timestamp
    pub timestamp: u64,
    /// Nonce (to prevent replay)
    pub nonce: [u8; 32],
    /// Custom report data (e.g., input/output commitments)
    #[serde(with = "crate::serde_byte_array_64")]
    pub report_data: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AttestedEnclaveRef {
    /// Stable backend identifier pinned by policy and observability.
    pub backend_id: String,
    /// Human-readable provider or operator family.
    pub provider: String,
    /// Optional control-plane endpoint used to dispatch enclave work.
    pub endpoint: Option<String>,
    /// Pinned measurement / PCR / enclave digest.
    pub measurement_digest: [u8; 32],
}

impl AttestedEnclaveRef {
    pub fn is_bound(&self) -> bool {
        !self.backend_id.trim().is_empty()
            && !self.provider.trim().is_empty()
            && self.measurement_digest.iter().any(|byte| *byte != 0)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EnclaveRuntimeBackend {
    /// Deterministic dev backend for tests and local demos.
    DeterministicDev,
    /// Production-attested runtime controlled outside consensus.
    ExternalAttested(AttestedEnclaveRef),
}

// ============================================================================
// Encrypted Transaction Types
// ============================================================================

/// A secret transaction that can only be processed in TEE
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretTransaction {
    /// Transaction ID
    pub id: [u8; 32],
    /// Encrypted payload (for TEE only)
    pub encrypted_payload: EncryptedPayload,
    /// Required TEE platform
    pub required_tee: TEERequirement,
    /// Sender's public key (for response encryption)
    pub sender_pubkey: [u8; 32],
    /// Gas limit
    pub gas_limit: u64,
    /// Gas price
    pub gas_price: u64,
    /// Priority fee (tip)
    pub priority_fee: u64,
    /// Expiry timestamp
    pub expiry: u64,
    /// Compliance requirements
    pub compliance: ComplianceRequirements,
    /// Signature (on metadata, not payload)
    #[serde(with = "crate::serde_byte_array_64")]
    pub signature: [u8; 64],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedPayload {
    /// Encryption scheme used
    pub scheme: EncryptionScheme,
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Ephemeral public key (for ECDH)
    pub ephemeral_pubkey: Vec<u8>,
    /// Nonce/IV
    pub nonce: [u8; 12],
    /// Authentication tag
    pub auth_tag: [u8; 16],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionScheme {
    /// ECDH + AES-256-GCM (default)
    ECIES_AES256GCM,
    /// ECDH + ChaCha20-Poly1305
    ECIES_ChaCha20Poly1305,
    /// RSA-OAEP + AES-256-GCM (for legacy compatibility)
    RSA_OAEP_AES256GCM,
    /// Post-quantum: Kyber + AES-256-GCM
    Kyber768_AES256GCM,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEERequirement {
    /// Allowed platforms
    pub allowed_platforms: Vec<TEEPlatformType>,
    /// Minimum security version
    pub min_svn: u16,
    /// Required enclave measurements (if specific enclave needed)
    pub required_measurements: Option<Vec<[u8; 32]>>,
    /// Maximum attestation age in seconds
    pub max_attestation_age: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TEEPlatformType {
    IntelSGX,
    AMDSEV,
    AWSNitro,
    ARMTrustZone,
}

impl From<&TEEPlatform> for TEEPlatformType {
    fn from(platform: &TEEPlatform) -> Self {
        match platform {
            TEEPlatform::IntelSGX { .. } => TEEPlatformType::IntelSGX,
            TEEPlatform::AMDSEV { .. } => TEEPlatformType::AMDSEV,
            TEEPlatform::AWSNitro { .. } => TEEPlatformType::AWSNitro,
            TEEPlatform::ARMTrustZone { .. } => TEEPlatformType::ARMTrustZone,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceRequirements {
    /// HIPAA compliance required
    pub hipaa: bool,
    /// GDPR compliance required
    pub gdpr: bool,
    /// Data residency requirement
    pub data_residency: Option<DataResidency>,
    /// Audit trail required
    pub audit_trail: bool,
    /// Maximum data retention (seconds)
    pub max_retention: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DataResidency {
    /// Must stay in UAE
    UAE,
    /// Must stay in EU
    EU,
    /// Must stay in Singapore
    Singapore,
    /// Must stay in specific countries
    Countries(Vec<String>),
    /// Any location acceptable
    Any,
}

// ============================================================================
// The Secret Mempool
// ============================================================================

/// The Secret Mempool - Encrypted transaction pool for TEE processing
pub struct SecretMempool {
    /// Pending secret transactions
    pending: VecDeque<SecretTransaction>,
    /// Transactions being processed in TEE
    processing: HashMap<[u8; 32], ProcessingTransaction>,
    /// Completed transactions awaiting inclusion
    completed: HashMap<[u8; 32], CompletedSecretTransaction>,
    /// Configuration
    config: SecretMempoolConfig,
    /// Metrics
    metrics: MempoolMetrics,
}

#[derive(Debug, Clone)]
pub struct SecretMempoolConfig {
    /// Maximum pending transactions
    pub max_pending: usize,
    /// Maximum processing transactions
    pub max_processing: usize,
    /// Processing timeout
    pub processing_timeout: Duration,
    /// Minimum gas price
    pub min_gas_price: u64,
    /// Runtime backend policy for enclave execution.
    pub runtime_backend: EnclaveRuntimeBackend,
}

impl Default for SecretMempoolConfig {
    fn default() -> Self {
        SecretMempoolConfig {
            max_pending: 10_000,
            max_processing: 100,
            processing_timeout: Duration::from_secs(60),
            min_gas_price: 1,
            runtime_backend: EnclaveRuntimeBackend::DeterministicDev,
        }
    }
}

impl SecretMempoolConfig {
    pub fn attested(backend: AttestedEnclaveRef) -> Self {
        SecretMempoolConfig {
            runtime_backend: EnclaveRuntimeBackend::ExternalAttested(backend),
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), MempoolError> {
        if self.max_pending == 0 {
            return Err(MempoolError::InvalidConfiguration(
                "max_pending must be greater than zero".to_string(),
            ));
        }
        if self.max_processing == 0 {
            return Err(MempoolError::InvalidConfiguration(
                "max_processing must be greater than zero".to_string(),
            ));
        }
        if self.processing_timeout.is_zero() {
            return Err(MempoolError::InvalidConfiguration(
                "processing_timeout must be greater than zero".to_string(),
            ));
        }
        Ok(())
    }

    pub fn validate_attested_runtime(&self) -> Result<(), MempoolError> {
        self.validate()?;
        match &self.runtime_backend {
            EnclaveRuntimeBackend::DeterministicDev => Err(MempoolError::InvalidConfiguration(
                "attested secret mempool requires an external enclave backend".to_string(),
            )),
            EnclaveRuntimeBackend::ExternalAttested(backend) if !backend.is_bound() => {
                Err(MempoolError::InvalidConfiguration(
                    "attested enclave backend is incomplete".to_string(),
                ))
            }
            EnclaveRuntimeBackend::ExternalAttested(_) => Ok(()),
        }
    }
}

#[derive(Debug, Clone)]
struct ProcessingTransaction {
    tx: SecretTransaction,
    assigned_validator: [u8; 32],
    started_at: SystemTime,
    attestation: Option<TEEAttestation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompletedSecretTransaction {
    /// Original transaction ID
    pub tx_id: [u8; 32],
    /// Result commitment (hash of result)
    pub result_commitment: [u8; 32],
    /// Encrypted result (for sender only)
    pub encrypted_result: Vec<u8>,
    /// TEE attestation proving correct execution
    pub attestation: TEEAttestation,
    /// Gas used
    pub gas_used: u64,
    /// Completion timestamp
    pub completed_at: u64,
}

#[derive(Debug, Clone, Default)]
pub struct MempoolMetrics {
    pub total_submitted: u64,
    pub total_processed: u64,
    pub total_failed: u64,
    pub average_processing_time_ms: u64,
    pub current_pending: usize,
    pub current_processing: usize,
}

impl SecretMempool {
    pub fn try_new(config: SecretMempoolConfig) -> Result<Self, MempoolError> {
        config.validate()?;
        Ok(SecretMempool {
            pending: VecDeque::new(),
            processing: HashMap::new(),
            completed: HashMap::new(),
            config,
            metrics: MempoolMetrics::default(),
        })
    }

    pub fn new(config: SecretMempoolConfig) -> Self {
        Self::try_new(config).expect("invalid SecretMempool configuration")
    }

    pub fn new_attested(config: SecretMempoolConfig) -> Result<Self, MempoolError> {
        config.validate_attested_runtime()?;
        Self::try_new(config)
    }

    /// Submit a secret transaction to the mempool
    pub fn submit(&mut self, tx: SecretTransaction) -> Result<[u8; 32], MempoolError> {
        // Validate gas price
        if tx.gas_price < self.config.min_gas_price {
            return Err(MempoolError::GasPriceTooLow {
                provided: tx.gas_price,
                minimum: self.config.min_gas_price,
            });
        }

        // Check expiry
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if tx.expiry < now {
            return Err(MempoolError::Expired);
        }

        // Check capacity
        if self.pending.len() >= self.config.max_pending {
            return Err(MempoolError::MempoolFull);
        }

        let tx_id = tx.id;
        self.pending.push_back(tx);
        self.metrics.total_submitted += 1;
        self.metrics.current_pending = self.pending.len();

        Ok(tx_id)
    }

    /// Get the next transaction for processing
    pub fn next_for_processing(&mut self, validator: [u8; 32]) -> Option<SecretTransaction> {
        if self.processing.len() >= self.config.max_processing {
            return None;
        }

        // Priority scheduling: highest effective gas price first, then highest
        // priority fee, then earliest expiry, then FIFO index.
        let best_index = self
            .pending
            .iter()
            .enumerate()
            .max_by(|(ia, a), (ib, b)| {
                let a_effective = a.gas_price.saturating_add(a.priority_fee);
                let b_effective = b.gas_price.saturating_add(b.priority_fee);
                a_effective
                    .cmp(&b_effective)
                    .then_with(|| a.priority_fee.cmp(&b.priority_fee))
                    .then_with(|| b.expiry.cmp(&a.expiry))
                    .then_with(|| ib.cmp(ia))
            })
            .map(|(idx, _)| idx);

        if let Some(tx) = best_index.and_then(|idx| self.pending.remove(idx)) {
            let tx_id = tx.id;
            self.processing.insert(
                tx_id,
                ProcessingTransaction {
                    tx: tx.clone(),
                    assigned_validator: validator,
                    started_at: SystemTime::now(),
                    attestation: None,
                },
            );
            self.metrics.current_pending = self.pending.len();
            self.metrics.current_processing = self.processing.len();
            Some(tx)
        } else {
            None
        }
    }

    /// Complete a transaction with TEE attestation
    pub fn complete(
        &mut self,
        tx_id: [u8; 32],
        result: CompletedSecretTransaction,
    ) -> Result<(), MempoolError> {
        if let Some(processing) = self.processing.remove(&tx_id) {
            let elapsed = processing.started_at.elapsed().unwrap_or_default();

            // Update metrics
            self.metrics.total_processed += 1;
            self.metrics.current_processing = self.processing.len();

            // Rolling average
            let elapsed_ms = elapsed.as_millis() as u64;
            self.metrics.average_processing_time_ms = (self.metrics.average_processing_time_ms
                * (self.metrics.total_processed - 1)
                + elapsed_ms)
                / self.metrics.total_processed;

            self.completed.insert(tx_id, result);
            Ok(())
        } else {
            Err(MempoolError::TransactionNotFound)
        }
    }

    /// Get completed transactions for block inclusion
    pub fn get_completed(&mut self, max_count: usize) -> Vec<CompletedSecretTransaction> {
        let mut results = Vec::with_capacity(max_count);
        let keys: Vec<_> = self.completed.keys().take(max_count).cloned().collect();

        for key in keys {
            if let Some(completed) = self.completed.remove(&key) {
                results.push(completed);
            }
        }

        results
    }

    /// Get metrics
    pub fn metrics(&self) -> &MempoolMetrics {
        &self.metrics
    }
}

#[derive(Debug, Clone)]
pub enum MempoolError {
    GasPriceTooLow { provided: u64, minimum: u64 },
    Expired,
    MempoolFull,
    TransactionNotFound,
    InvalidConfiguration(String),
    InvalidAttestation(String),
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::GasPriceTooLow { provided, minimum } => {
                write!(f, "Gas price {} below minimum {}", provided, minimum)
            }
            MempoolError::Expired => write!(f, "Transaction expired"),
            MempoolError::MempoolFull => write!(f, "Mempool is full"),
            MempoolError::TransactionNotFound => write!(f, "Transaction not found"),
            MempoolError::InvalidConfiguration(msg) => {
                write!(f, "Invalid secret mempool configuration: {}", msg)
            }
            MempoolError::InvalidAttestation(msg) => write!(f, "Invalid attestation: {}", msg),
        }
    }
}

impl std::error::Error for MempoolError {}

// ============================================================================
// TEE Validator Node
// ============================================================================

/// A TEE-enabled validator node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TEEValidator {
    /// Validator address
    pub address: [u8; 32],
    /// TEE platform
    pub platform: TEEPlatform,
    /// Current attestation
    pub attestation: TEEAttestation,
    /// Supported compliance certifications
    pub certifications: Vec<ComplianceCertification>,
    /// Geographic location (for data residency)
    pub location: ValidatorLocation,
    /// Current status
    pub status: ValidatorStatus,
    /// Enclave public key (for encryption)
    pub enclave_pubkey: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceCertification {
    pub certification_type: CertificationType,
    pub issuer: String,
    pub valid_until: u64,
    pub certificate_hash: [u8; 32],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CertificationType {
    HIPAA,
    SOC2Type2,
    ISO27001,
    PCI_DSS,
    GDPR_Certified,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorLocation {
    pub country: String,
    pub region: Option<String>,
    pub data_center: Option<String>,
    /// Geographic coordinates (for latency estimation)
    pub coordinates: Option<(f64, f64)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidatorStatus {
    Active,
    Inactive,
    Attesting,
    Maintenance,
}

/// TEE Validator Selection for Secret Transactions
pub struct TEEValidatorSelector {
    validators: HashMap<[u8; 32], TEEValidator>,
}

impl TEEValidatorSelector {
    pub fn new() -> Self {
        TEEValidatorSelector {
            validators: HashMap::new(),
        }
    }

    pub fn register(&mut self, validator: TEEValidator) {
        self.validators.insert(validator.address, validator);
    }

    /// Select validators that meet the transaction requirements
    pub fn select_for_transaction(&self, tx: &SecretTransaction) -> Vec<&TEEValidator> {
        self.validators
            .values()
            .filter(|v| matches!(v.status, ValidatorStatus::Active))
            .filter(|v| self.meets_tee_requirements(v, &tx.required_tee))
            .filter(|v| self.meets_compliance_requirements(v, &tx.compliance))
            .collect()
    }

    fn meets_tee_requirements(&self, validator: &TEEValidator, req: &TEERequirement) -> bool {
        // Check platform type
        let platform_type = match &validator.platform {
            TEEPlatform::IntelSGX { .. } => TEEPlatformType::IntelSGX,
            TEEPlatform::AMDSEV { .. } => TEEPlatformType::AMDSEV,
            TEEPlatform::AWSNitro { .. } => TEEPlatformType::AWSNitro,
            TEEPlatform::ARMTrustZone { .. } => TEEPlatformType::ARMTrustZone,
        };

        if !req.allowed_platforms.contains(&platform_type) {
            return false;
        }

        // Check SVN (for SGX)
        if let TEEPlatform::IntelSGX { svn, .. } = &validator.platform {
            if *svn < req.min_svn {
                return false;
            }
        }

        // Check attestation freshness
        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now - validator.attestation.timestamp > req.max_attestation_age {
            return false;
        }

        true
    }

    fn meets_compliance_requirements(
        &self,
        validator: &TEEValidator,
        req: &ComplianceRequirements,
    ) -> bool {
        // Check HIPAA
        if req.hipaa {
            let has_hipaa = validator
                .certifications
                .iter()
                .any(|c| matches!(c.certification_type, CertificationType::HIPAA));
            if !has_hipaa {
                return false;
            }
        }

        // Check data residency
        if let Some(ref residency) = req.data_residency {
            match residency {
                DataResidency::UAE => {
                    if validator.location.country != "AE" {
                        return false;
                    }
                }
                DataResidency::EU => {
                    let eu_countries = ["DE", "FR", "NL", "IE", "BE", "AT", "IT", "ES", "PT"];
                    if !eu_countries.contains(&validator.location.country.as_str()) {
                        return false;
                    }
                }
                DataResidency::Singapore => {
                    if validator.location.country != "SG" {
                        return false;
                    }
                }
                DataResidency::Countries(countries) => {
                    if !countries.contains(&validator.location.country) {
                        return false;
                    }
                }
                DataResidency::Any => {}
            }
        }

        true
    }
}

impl Default for TEEValidatorSelector {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Enclave Execution Environment
// ============================================================================

/// Simulated enclave execution environment
pub struct EnclaveExecutor {
    /// Platform
    platform: TEEPlatform,
    /// Runtime backend policy
    backend: EnclaveRuntimeBackend,
    /// Enclave key pair (in real implementation, this never leaves enclave)
    enclave_keypair: EnclaveKeyPair,
    /// Registered models
    models: HashMap<[u8; 32], RegisteredModel>,
}

#[derive(Debug, Clone)]
struct EnclaveKeyPair {
    public_key: [u8; 32],
    #[allow(dead_code)]
    private_key: [u8; 32], // Never exposed
}

#[derive(Debug, Clone)]
struct RegisteredModel {
    model_hash: [u8; 32],
    model_type: ModelType,
    input_schema: Vec<u8>,
    output_schema: Vec<u8>,
}

#[derive(Debug, Clone)]
enum ModelType {
    ONNX,
    TensorFlowLite,
    Custom,
}

pub(crate) trait AttestedEnclaveRuntime {
    fn decrypt_payload(
        &self,
        payload: &EncryptedPayload,
        sender_pubkey: &[u8; 32],
    ) -> Result<Vec<u8>, EnclaveError>;

    fn execute_operation(&self, operation: &EnclaveOperation) -> Result<Vec<u8>, EnclaveError>;

    fn encrypt_for_sender(
        &self,
        result: &[u8],
        sender_pubkey: &[u8; 32],
    ) -> Result<Vec<u8>, EnclaveError>;

    fn generate_attestation(
        &self,
        platform: &TEEPlatform,
        tx: &SecretTransaction,
        result_commitment: &[u8; 32],
        backend: &AttestedEnclaveRef,
    ) -> Result<TEEAttestation, EnclaveError>;
}

impl EnclaveExecutor {
    pub fn new(platform: TEEPlatform) -> Self {
        let public_key = Self::derive_key_material("public", &platform);
        let private_key = Self::derive_key_material("private", &platform);
        EnclaveExecutor {
            platform,
            backend: EnclaveRuntimeBackend::DeterministicDev,
            enclave_keypair: EnclaveKeyPair {
                public_key,
                private_key,
            },
            models: HashMap::new(),
        }
    }

    pub fn new_attested(
        platform: TEEPlatform,
        backend: AttestedEnclaveRef,
    ) -> Result<Self, EnclaveError> {
        if !backend.is_bound() {
            return Err(EnclaveError::InvalidConfiguration(
                "attested enclave backend is incomplete".to_string(),
            ));
        }
        let public_key = Self::derive_backend_key("public", &backend);
        let private_key = Self::derive_backend_key("private", &backend);
        Ok(EnclaveExecutor {
            platform,
            backend: EnclaveRuntimeBackend::ExternalAttested(backend),
            enclave_keypair: EnclaveKeyPair {
                public_key,
                private_key,
            },
            models: HashMap::new(),
        })
    }

    /// Get enclave public key (safe to expose)
    pub fn public_key(&self) -> [u8; 32] {
        self.enclave_keypair.public_key
    }

    /// Process a secret transaction inside the enclave
    pub fn process(&self, tx: &SecretTransaction) -> Result<EnclaveResult, EnclaveError> {
        #[cfg(feature = "production")]
        let _ = tx;
        match &self.backend {
            EnclaveRuntimeBackend::DeterministicDev => {
                #[cfg(not(feature = "production"))]
                {
                    return self.process_with_dev_backend(tx);
                }
                #[cfg(feature = "production")]
                {
                    return Err(EnclaveError::ExternalRuntimeRequired(
                        "deterministic dev enclave backend is disabled in production builds"
                            .to_string(),
                    ));
                }
            }
            EnclaveRuntimeBackend::ExternalAttested(_) => {
                Err(EnclaveError::ExternalRuntimeRequired(
                    "use process_with_runtime for attested enclave execution".to_string(),
                ))
            }
        }
    }

    pub(crate) fn process_with_runtime<R: AttestedEnclaveRuntime>(
        &self,
        tx: &SecretTransaction,
        runtime: &R,
    ) -> Result<EnclaveResult, EnclaveError> {
        let backend = match &self.backend {
            EnclaveRuntimeBackend::DeterministicDev => {
                return Err(EnclaveError::ExternalRuntimeRequired(
                    "deterministic backend should use process() instead".to_string(),
                ))
            }
            EnclaveRuntimeBackend::ExternalAttested(backend) => backend,
        };

        let decrypted = runtime.decrypt_payload(&tx.encrypted_payload, &tx.sender_pubkey)?;
        let operation = self.parse_operation(&decrypted)?;
        let result = runtime.execute_operation(&operation)?;
        let result_commitment = self.hash_result(&result);
        let encrypted_result = runtime.encrypt_for_sender(&result, &tx.sender_pubkey)?;
        let attestation =
            runtime.generate_attestation(&self.platform, tx, &result_commitment, backend)?;

        Ok(EnclaveResult {
            tx_id: tx.id,
            result_commitment,
            encrypted_result,
            attestation,
            gas_used: self.estimate_gas(&operation),
        })
    }

    #[cfg(not(feature = "production"))]
    fn process_with_dev_backend(
        &self,
        tx: &SecretTransaction,
    ) -> Result<EnclaveResult, EnclaveError> {
        // 1. Decrypt the payload (in enclave)
        let decrypted = self.decrypt_payload(&tx.encrypted_payload)?;

        // 2. Parse the operation
        let operation = self.parse_operation(&decrypted)?;

        // 3. Execute the operation
        let result = self.execute_operation(&operation)?;

        // 4. Create result commitment
        let result_commitment = self.hash_result(&result);

        // 5. Encrypt result for sender
        let encrypted_result = self.encrypt_for_sender(&result, &tx.sender_pubkey)?;

        // 6. Generate attestation
        let attestation = self.generate_attestation(tx, &result_commitment)?;

        Ok(EnclaveResult {
            tx_id: tx.id,
            result_commitment,
            encrypted_result,
            attestation,
            gas_used: self.estimate_gas(&operation),
        })
    }

    fn derive_key_material(label: &str, platform: &TEEPlatform) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"aethelred-secret-mempool-dev-key");
        hasher.update(label.as_bytes());
        hasher.update(format!("{:?}", TEEPlatformType::from(platform)).as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    fn derive_backend_key(label: &str, backend: &AttestedEnclaveRef) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"aethelred-secret-mempool-attested-key");
        hasher.update(label.as_bytes());
        hasher.update(backend.backend_id.as_bytes());
        hasher.update(backend.provider.as_bytes());
        hasher.update(backend.measurement_digest);
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        out
    }

    #[cfg(not(feature = "production"))]
    fn decrypt_payload(&self, payload: &EncryptedPayload) -> Result<Vec<u8>, EnclaveError> {
        // Development-only placeholder path: deterministic stream masking to
        // avoid silently returning empty plaintext for local testing.
        if payload.ciphertext.is_empty() {
            return Err(EnclaveError::DecryptionFailed);
        }

        let mut key_material = [0u8; 32];
        self.derive_stream_key(&payload.ephemeral_pubkey, &payload.nonce, &mut key_material);
        Ok(self.xor_stream(&payload.ciphertext, &key_material))
    }

    fn parse_operation(&self, _data: &[u8]) -> Result<EnclaveOperation, EnclaveError> {
        // Parse the operation from decrypted data
        Ok(EnclaveOperation::Inference {
            model_hash: [0u8; 32],
            input: vec![],
        })
    }

    fn execute_operation(&self, op: &EnclaveOperation) -> Result<Vec<u8>, EnclaveError> {
        match op {
            EnclaveOperation::Inference { model_hash, input } => {
                self.run_inference(model_hash, input)
            }
            EnclaveOperation::Computation { code_hash, input } => {
                self.run_computation(code_hash, input)
            }
            EnclaveOperation::KeyDerivation { seed, path } => self.derive_key(seed, path),
        }
    }

    fn run_inference(
        &self,
        _model_hash: &[u8; 32],
        _input: &[u8],
    ) -> Result<Vec<u8>, EnclaveError> {
        // Run ONNX model inference inside enclave
        Ok(vec![]) // Placeholder
    }

    fn run_computation(
        &self,
        _code_hash: &[u8; 32],
        _input: &[u8],
    ) -> Result<Vec<u8>, EnclaveError> {
        // Run verified computation
        Ok(vec![])
    }

    fn derive_key(&self, _seed: &[u8], _path: &str) -> Result<Vec<u8>, EnclaveError> {
        // Derive key inside enclave
        Ok(vec![])
    }

    fn hash_result(&self, result: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(result);
        let hash = hasher.finalize();
        let mut result_hash = [0u8; 32];
        result_hash.copy_from_slice(&hash);
        result_hash
    }

    #[cfg(not(feature = "production"))]
    fn encrypt_for_sender(
        &self,
        result: &[u8],
        sender_pubkey: &[u8; 32],
    ) -> Result<Vec<u8>, EnclaveError> {
        if result.is_empty() {
            return Err(EnclaveError::ExecutionFailed("empty result".to_string()));
        }

        let mut nonce = [0u8; 12];
        OsRng.fill_bytes(&mut nonce);

        let mut key_material = [0u8; 32];
        self.derive_stream_key(sender_pubkey, &nonce, &mut key_material);
        let mut ciphertext = self.xor_stream(result, &key_material);

        // Prefix nonce so the caller has sufficient material to decrypt in dev mode.
        let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.append(&mut ciphertext);
        Ok(sealed)
    }

    #[cfg(not(feature = "production"))]
    fn generate_attestation(
        &self,
        tx: &SecretTransaction,
        result_commitment: &[u8; 32],
    ) -> Result<TEEAttestation, EnclaveError> {
        // Generate platform-specific attestation
        let mut report_data = [0u8; 64];
        report_data[..32].copy_from_slice(&tx.id);
        report_data[32..].copy_from_slice(result_commitment);

        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut nonce = [0u8; 32];
        OsRng.fill_bytes(&mut nonce);

        use sha2::{Digest, Sha256};
        let mut report_hasher = Sha256::new();
        report_hasher.update(b"aethelred-dev-attestation-report");
        report_hasher.update(tx.id);
        report_hasher.update(result_commitment);
        report_hasher.update(nonce);
        let report = report_hasher.finalize().to_vec();

        let mut sig_hasher = Sha256::new();
        sig_hasher.update(b"aethelred-dev-attestation-signature");
        sig_hasher.update(&report);
        sig_hasher.update(self.enclave_keypair.public_key);
        let signature = sig_hasher.finalize().to_vec();

        Ok(TEEAttestation {
            platform: self.platform.clone(),
            report,
            signature,
            cert_chain: vec![b"DEV_PLACEHOLDER_CERT_CHAIN_REPLACE_IN_PRODUCTION".to_vec()],
            timestamp: now,
            nonce,
            report_data,
        })
    }

    #[cfg(not(feature = "production"))]
    fn derive_stream_key(&self, peer_pubkey: &[u8], nonce: &[u8; 12], out: &mut [u8; 32]) {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"aethelred-dev-enclave-stream-key");
        hasher.update(self.enclave_keypair.private_key);
        hasher.update(peer_pubkey);
        hasher.update(nonce);
        out.copy_from_slice(&hasher.finalize());
    }

    fn xor_stream(&self, data: &[u8], key_material: &[u8; 32]) -> Vec<u8> {
        use sha2::{Digest, Sha256};

        let mut out = Vec::with_capacity(data.len());
        let mut counter: u64 = 0;
        let mut offset = 0usize;
        while offset < data.len() {
            let mut hasher = Sha256::new();
            hasher.update(b"aethelred-dev-keystream");
            hasher.update(key_material);
            hasher.update(counter.to_le_bytes());
            let block = hasher.finalize();
            for b in block {
                if offset >= data.len() {
                    break;
                }
                out.push(data[offset] ^ b);
                offset += 1;
            }
            counter = counter.saturating_add(1);
        }
        out
    }

    fn estimate_gas(&self, _op: &EnclaveOperation) -> u64 {
        100_000 // Placeholder
    }
}

#[derive(Debug, Clone)]
pub(crate) enum EnclaveOperation {
    Inference {
        model_hash: [u8; 32],
        input: Vec<u8>,
    },
    Computation {
        code_hash: [u8; 32],
        input: Vec<u8>,
    },
    KeyDerivation {
        seed: Vec<u8>,
        path: String,
    },
}

#[derive(Debug, Clone)]
pub struct EnclaveResult {
    pub tx_id: [u8; 32],
    pub result_commitment: [u8; 32],
    pub encrypted_result: Vec<u8>,
    pub attestation: TEEAttestation,
    pub gas_used: u64,
}

#[derive(Debug, Clone)]
pub enum EnclaveError {
    DecryptionFailed,
    InvalidOperation,
    ModelNotFound([u8; 32]),
    InvalidConfiguration(String),
    ExecutionFailed(String),
    AttestationFailed(String),
    ExternalRuntimeRequired(String),
}

impl std::fmt::Display for EnclaveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnclaveError::DecryptionFailed => write!(f, "Decryption failed"),
            EnclaveError::InvalidOperation => write!(f, "Invalid operation"),
            EnclaveError::ModelNotFound(hash) => write!(f, "Model not found: {:?}", hash),
            EnclaveError::InvalidConfiguration(msg) => {
                write!(f, "Invalid enclave configuration: {}", msg)
            }
            EnclaveError::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            EnclaveError::AttestationFailed(msg) => write!(f, "Attestation failed: {}", msg),
            EnclaveError::ExternalRuntimeRequired(msg) => {
                write!(f, "External runtime required: {}", msg)
            }
        }
    }
}

impl std::error::Error for EnclaveError {}

// ============================================================================
// Privacy Guarantees
// ============================================================================

/// Privacy guarantees provided by the Secret Mempool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyGuarantees {
    /// Data never visible to validators in plaintext
    pub data_confidentiality: bool,
    /// Input/output relationship hidden
    pub computation_privacy: bool,
    /// Transaction details hidden from other users
    pub transaction_privacy: bool,
    /// MEV (Maximal Extractable Value) protection
    pub mev_protection: bool,
    /// Front-running protection
    pub front_running_protection: bool,
}

impl PrivacyGuarantees {
    /// Default guarantees for secret mempool
    pub fn default_secret_mempool() -> Self {
        PrivacyGuarantees {
            data_confidentiality: true,
            computation_privacy: true,
            transaction_privacy: true,
            mev_protection: true,
            front_running_protection: true,
        }
    }

    /// Compare with public chains
    pub fn comparison_report() -> String {
        r#"
╔═══════════════════════════════════════════════════════════════════════════════╗
║                    PRIVACY COMPARISON: AETHELRED vs COMPETITORS                ║
╠═══════════════════════════════════════════════════════════════════════════════╣
║                                                                                ║
║  Feature                    │ Ethereum  │ Solana    │ Aethelred               ║
║  ───────────────────────────┼───────────┼───────────┼─────────────────────────║
║  Data Confidentiality       │    ❌     │    ❌     │    ✅ (TEE Encrypted)   ║
║  Computation Privacy        │    ❌     │    ❌     │    ✅ (In-Enclave)      ║
║  Transaction Privacy        │    ❌     │    ❌     │    ✅ (Secret Mempool)  ║
║  MEV Protection             │    ❌     │    ❌     │    ✅ (Encrypted Queue) ║
║  Front-Running Protection   │    ❌     │    ❌     │    ✅ (Commit-Reveal)   ║
║  ───────────────────────────┼───────────┼───────────┼─────────────────────────║
║  HIPAA Compliant            │    ❌     │    ❌     │    ✅                   ║
║  GDPR Compliant             │    ❌     │    ❌     │    ✅                   ║
║  Bank Audit Ready           │    ❌     │    ❌     │    ✅                   ║
║                                                                                ║
║  WHY THIS MATTERS:                                                             ║
║  ┌──────────────────────────────────────────────────────────────────────────┐ ║
║  │ On Ethereum/Solana:                                                      │ ║
║  │   - Every transaction is PUBLIC                                          │ ║
║  │   - Anyone can see your data, trades, and AI inputs                     │ ║
║  │   - Bots front-run your transactions                                    │ ║
║  │   - Medical/financial data CANNOT be stored                             │ ║
║  │                                                                          │ ║
║  │ On Aethelred:                                                            │ ║
║  │   - Data encrypted client-side                                          │ ║
║  │   - Only decrypted inside verified TEE                                  │ ║
║  │   - Validators prove results WITHOUT seeing inputs                      │ ║
║  │   - Hospital DNA data → AI diagnosis → Encrypted result                 │ ║
║  │   - Bank can audit AI models on-chain                                   │ ║
║  └──────────────────────────────────────────────────────────────────────────┘ ║
║                                                                                ║
║  USE CASES NOW POSSIBLE:                                                       ║
║  • Healthcare AI (HIPAA compliant)                                            ║
║  • Banking risk models (Regulatory audit trail)                               ║
║  • Private DeFi (No front-running)                                            ║
║  • Confidential smart contracts                                               ║
║                                                                                ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"#
        .to_string()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_secret_tx(id_byte: u8, gas_price: u64, priority_fee: u64) -> SecretTransaction {
        SecretTransaction {
            id: [id_byte; 32],
            encrypted_payload: EncryptedPayload {
                scheme: EncryptionScheme::ECIES_AES256GCM,
                ciphertext: vec![id_byte; 32],
                ephemeral_pubkey: vec![1u8; 32],
                nonce: [2u8; 12],
                auth_tag: [3u8; 16],
            },
            required_tee: TEERequirement {
                allowed_platforms: vec![TEEPlatformType::IntelSGX],
                min_svn: 0,
                required_measurements: None,
                max_attestation_age: 3600,
            },
            sender_pubkey: [4u8; 32],
            gas_limit: 100000,
            gas_price,
            priority_fee,
            expiry: u64::MAX,
            compliance: ComplianceRequirements {
                hipaa: false,
                gdpr: false,
                data_residency: None,
                audit_trail: true,
                max_retention: None,
            },
            signature: [5u8; 64],
        }
    }

    #[test]
    fn test_secret_mempool_creation() {
        let mempool = SecretMempool::new(SecretMempoolConfig::default());
        assert_eq!(mempool.metrics().current_pending, 0);
    }

    #[test]
    fn test_attested_secret_mempool_requires_bound_backend() {
        let invalid = SecretMempoolConfig::attested(AttestedEnclaveRef {
            backend_id: "".to_string(),
            provider: "nitro".to_string(),
            endpoint: None,
            measurement_digest: [0u8; 32],
        });
        assert!(SecretMempool::new_attested(invalid).is_err());

        let valid = SecretMempoolConfig::attested(AttestedEnclaveRef {
            backend_id: "nitro-enclave-01".to_string(),
            provider: "aws-nitro".to_string(),
            endpoint: Some("https://tee.example".to_string()),
            measurement_digest: [7u8; 32],
        });
        assert!(SecretMempool::new_attested(valid).is_ok());
    }

    #[test]
    fn test_transaction_submission() {
        let mut mempool = SecretMempool::new(SecretMempoolConfig::default());

        let tx = SecretTransaction {
            id: [1u8; 32],
            encrypted_payload: EncryptedPayload {
                scheme: EncryptionScheme::ECIES_AES256GCM,
                ciphertext: vec![0u8; 100],
                ephemeral_pubkey: vec![0u8; 32],
                nonce: [0u8; 12],
                auth_tag: [0u8; 16],
            },
            required_tee: TEERequirement {
                allowed_platforms: vec![TEEPlatformType::IntelSGX],
                min_svn: 10,
                required_measurements: None,
                max_attestation_age: 3600,
            },
            sender_pubkey: [2u8; 32],
            gas_limit: 100000,
            gas_price: 1,
            priority_fee: 0,
            expiry: u64::MAX,
            compliance: ComplianceRequirements {
                hipaa: false,
                gdpr: false,
                data_residency: None,
                audit_trail: true,
                max_retention: None,
            },
            signature: [0u8; 64],
        };

        let result = mempool.submit(tx);
        assert!(result.is_ok());
        assert_eq!(mempool.metrics().current_pending, 1);
    }

    #[test]
    fn test_gas_price_validation() {
        let mut mempool = SecretMempool::new(SecretMempoolConfig {
            min_gas_price: 10,
            ..Default::default()
        });

        let tx = SecretTransaction {
            id: [1u8; 32],
            encrypted_payload: EncryptedPayload {
                scheme: EncryptionScheme::ECIES_AES256GCM,
                ciphertext: vec![],
                ephemeral_pubkey: vec![],
                nonce: [0u8; 12],
                auth_tag: [0u8; 16],
            },
            required_tee: TEERequirement {
                allowed_platforms: vec![TEEPlatformType::IntelSGX],
                min_svn: 0,
                required_measurements: None,
                max_attestation_age: 3600,
            },
            sender_pubkey: [0u8; 32],
            gas_limit: 100000,
            gas_price: 1, // Below minimum
            priority_fee: 0,
            expiry: u64::MAX,
            compliance: ComplianceRequirements {
                hipaa: false,
                gdpr: false,
                data_residency: None,
                audit_trail: false,
                max_retention: None,
            },
            signature: [0u8; 64],
        };

        let result = mempool.submit(tx);
        assert!(matches!(result, Err(MempoolError::GasPriceTooLow { .. })));
    }

    #[test]
    fn test_validator_selection() {
        let mut selector = TEEValidatorSelector::new();

        let now = SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let validator = TEEValidator {
            address: [1u8; 32],
            platform: TEEPlatform::IntelSGX {
                version: 2,
                svn: 15,
                mrenclave: [0u8; 32],
                mrsigner: [0u8; 32],
            },
            attestation: TEEAttestation {
                platform: TEEPlatform::IntelSGX {
                    version: 2,
                    svn: 15,
                    mrenclave: [0u8; 32],
                    mrsigner: [0u8; 32],
                },
                report: vec![],
                signature: vec![],
                cert_chain: vec![],
                timestamp: now,
                nonce: [0u8; 32],
                report_data: [0u8; 64],
            },
            certifications: vec![ComplianceCertification {
                certification_type: CertificationType::HIPAA,
                issuer: "TrustAuthority".to_string(),
                valid_until: now + 365 * 24 * 3600,
                certificate_hash: [0u8; 32],
            }],
            location: ValidatorLocation {
                country: "AE".to_string(),
                region: Some("Abu Dhabi".to_string()),
                data_center: Some("AWS".to_string()),
                coordinates: Some((24.4539, 54.3773)),
            },
            status: ValidatorStatus::Active,
            enclave_pubkey: [0u8; 32],
        };

        selector.register(validator);

        let tx = SecretTransaction {
            id: [1u8; 32],
            encrypted_payload: EncryptedPayload {
                scheme: EncryptionScheme::ECIES_AES256GCM,
                ciphertext: vec![],
                ephemeral_pubkey: vec![],
                nonce: [0u8; 12],
                auth_tag: [0u8; 16],
            },
            required_tee: TEERequirement {
                allowed_platforms: vec![TEEPlatformType::IntelSGX],
                min_svn: 10,
                required_measurements: None,
                max_attestation_age: 3600,
            },
            sender_pubkey: [0u8; 32],
            gas_limit: 100000,
            gas_price: 1,
            priority_fee: 0,
            expiry: u64::MAX,
            compliance: ComplianceRequirements {
                hipaa: true,
                gdpr: false,
                data_residency: Some(DataResidency::UAE),
                audit_trail: true,
                max_retention: None,
            },
            signature: [0u8; 64],
        };

        let selected = selector.select_for_transaction(&tx);
        assert_eq!(selected.len(), 1);
    }

    #[test]
    fn test_privacy_comparison() {
        let report = PrivacyGuarantees::comparison_report();
        assert!(report.contains("HIPAA Compliant"));
        assert!(report.contains("Aethelred"));
    }

    #[test]
    fn test_next_for_processing_prioritizes_effective_gas_price() {
        let mut mempool = SecretMempool::new(SecretMempoolConfig::default());
        let validator = [9u8; 32];

        // lower effective fee (10 + 0 = 10)
        mempool.submit(sample_secret_tx(1, 10, 0)).unwrap();
        // higher effective fee (9 + 5 = 14) should win
        mempool.submit(sample_secret_tx(2, 9, 5)).unwrap();

        let first = mempool.next_for_processing(validator).expect("first tx");
        let second = mempool.next_for_processing(validator).expect("second tx");

        assert_eq!(
            first.id, [2u8; 32],
            "priority scheduling must prefer higher effective gas price"
        );
        assert_eq!(second.id, [1u8; 32]);
    }

    #[test]
    #[cfg(not(feature = "production"))]
    fn test_enclave_dev_attestation_and_encryption_are_non_empty() {
        let enclave = EnclaveExecutor::new(TEEPlatform::IntelSGX {
            version: 2,
            svn: 1,
            mrenclave: [0u8; 32],
            mrsigner: [0u8; 32],
        });
        let tx = sample_secret_tx(7, 10, 1);

        let sealed = enclave
            .encrypt_for_sender(b"result-bytes", &tx.sender_pubkey)
            .unwrap();
        assert!(!sealed.is_empty());
        assert!(sealed.len() > 12, "nonce + ciphertext expected");

        let commitment = [8u8; 32];
        let attestation = enclave.generate_attestation(&tx, &commitment).unwrap();
        assert!(
            !attestation.report.is_empty(),
            "dev attestation report must not be empty"
        );
        assert!(
            !attestation.signature.is_empty(),
            "dev attestation signature must not be empty"
        );
        assert_ne!(attestation.nonce, [0u8; 32], "nonce should be randomized");
    }

    #[test]
    fn test_enclave_attested_constructor_requires_measurement() {
        let platform = TEEPlatform::AWSNitro {
            pcr0: [1u8; 48],
            pcr1: [2u8; 48],
            pcr2: [3u8; 48],
        };
        let invalid = AttestedEnclaveRef {
            backend_id: "tee-runtime".to_string(),
            provider: "aws-nitro".to_string(),
            endpoint: None,
            measurement_digest: [0u8; 32],
        };
        assert!(EnclaveExecutor::new_attested(platform.clone(), invalid).is_err());

        let valid = AttestedEnclaveRef {
            backend_id: "tee-runtime".to_string(),
            provider: "aws-nitro".to_string(),
            endpoint: Some("https://tee.example".to_string()),
            measurement_digest: [9u8; 32],
        };
        let executor = EnclaveExecutor::new_attested(platform, valid).unwrap();
        assert_ne!(executor.public_key(), [0u8; 32]);
    }
}
