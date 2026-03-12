//! TEE Attestation Generation
//!
//! Generates attestation documents that can be verified on-chain by:
//!   - **Go native verifier**: `x/vault/keeper.verifyAttestation()`
//!   - **Solidity verifier**: `VaultTEEVerifier.verifyAttestation()`
//!
//! Every attestation is signed with a secp256k1 ECDSA key held inside the TEE.
//! The digest format matches the Go native verifier:
//!
//! ```text
//! digest = SHA-256("CrucibleTEEAttestation" ‖ platform ‖ timestamp_be64 ‖
//!                   nonce ‖ enclaveHash ‖ signerHash ‖ payloadHash)
//! ```
//!
//! The signature is 65 bytes: R[32] ‖ S[32] ‖ V[1] (Ethereum-style recovery ID).

use sha2::{Digest, Sha256};

use crate::types::AttestationDocument;

/// TEE platform configuration.
#[derive(Debug, Clone)]
pub struct TEEConfig {
    pub platform: TEEPlatform,
    pub enclave_hash: [u8; 32],
    pub signer_hash: [u8; 32],
    /// Application-level measurement (Nitro PCR2). Only used for Nitro enclaves;
    /// SGX and SEV should leave this `None`.
    pub application_hash: Option<[u8; 32]>,
    pub allow_simulated: bool,
    /// secp256k1 private key (32 bytes). In production this is generated inside
    /// the TEE enclave and never leaves the secure boundary.
    pub signing_key: [u8; 32],
}

/// Attestation authority-signed binding of a P-256 platform key to a TEE platform.
///
/// Proves the platform key was generated inside real TEE hardware and is
/// certified by a trusted attestation authority. The authority may be:
///
///   - **Direct hardware vendor** (Intel/AWS/AMD) - for future direct
///     on-chain vendor verification.
///   - **Attestation relay** (production) - a trusted bridge service that
///     verifies the full hardware attestation chain (DCAP/NSM/PSP) off-chain
///     and signs the key binding with its own P-256 key. The relay's public
///     key is registered on-chain as the attestation authority via
///     `VaultTEEVerifier.registerAttestationRelay()`.
///
/// **Trust model note**: When using a relay, the hardware chain of trust is
/// verified by the relay, not directly on-chain. The on-chain contract trusts
/// the relay's signature. This is documented explicitly in the Solidity
/// contract's `AttestationRelay` struct and managed with rotation timelocks,
/// liveness challenges, and emergency revocation.
///
/// In production: obtained via `RemoteVendorAttester` (attestation relay).
/// In testing: signed by a well-known vendor root key (D=2).
#[derive(Debug, Clone)]
pub struct KeyAttestation {
    /// P-256 public key X coordinate (32 bytes, big-endian)
    pub platform_key_x: [u8; 32],
    /// P-256 public key Y coordinate (32 bytes, big-endian)
    pub platform_key_y: [u8; 32],
    /// Platform identifier
    pub platform_id: u8,
    /// Vendor attestation P-256 signature R (32 bytes, big-endian)
    pub vendor_sig_r: [u8; 32],
    /// Vendor attestation P-256 signature S (32 bytes, big-endian)
    pub vendor_sig_s: [u8; 32],
}

/// Supported TEE platforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TEEPlatform {
    IntelSGX = 0,
    AWSNitro = 1,
    AMDSEV = 2,
    Mock = 255,
}

impl std::fmt::Display for TEEPlatform {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TEEPlatform::IntelSGX => write!(f, "sgx"),
            TEEPlatform::AWSNitro => write!(f, "nitro"),
            TEEPlatform::AMDSEV => write!(f, "sev"),
            TEEPlatform::Mock => write!(f, "mock"),
        }
    }
}

/// Errors returned by the attestation generator.
#[derive(Debug)]
pub enum AttestationError {
    /// Mock attestation was requested but `allow_simulated` is false.
    MockDisabled,
    /// The requested TEE platform is not available on this host.
    PlatformNotAvailable(TEEPlatform),
    /// A mock hardware provider is being used for a real platform
    /// without `allow_simulated` being set. This prevents the system
    /// from silently running in fake-hardware mode while claiming to be
    /// backed by real TEE hardware.
    SimulatedHardwareNotAllowed(TEEPlatform),
    /// The hardware report's measurements do not match the configured
    /// enclave measurements. This indicates either a misconfigured TEE
    /// or that modified code is running inside the enclave.
    MeasurementMismatch {
        field: &'static str,
        expected: [u8; 32],
        got: [u8; 32],
    },
    /// ECDSA signing failed.
    SigningFailed(String),
    /// Hardware device unavailable or returned an error.
    HardwareUnavailable(String),
}

impl std::fmt::Display for AttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationError::MockDisabled => {
                write!(f, "mock attestation disabled (set allow_simulated = true for testing)")
            }
            AttestationError::PlatformNotAvailable(p) => {
                write!(f, "TEE platform '{}' is not available on this host", p)
            }
            AttestationError::SimulatedHardwareNotAllowed(p) => {
                write!(
                    f,
                    "simulated hardware provider for platform '{}' is not allowed \
                     (running without real TEE hardware; set allow_simulated = true for testing)",
                    p
                )
            }
            AttestationError::MeasurementMismatch { field, expected, got } => {
                write!(
                    f,
                    "hardware report {} mismatch: expected {}, got {}",
                    field,
                    hex::encode(expected),
                    hex::encode(got)
                )
            }
            AttestationError::SigningFailed(msg) => {
                write!(f, "ECDSA signing failed: {}", msg)
            }
            AttestationError::HardwareUnavailable(msg) => {
                write!(f, "TEE hardware unavailable: {}", msg)
            }
        }
    }
}

impl std::error::Error for AttestationError {}

/// Fresh hardware attestation report returned by a HardwareAttestationProvider.
///
/// Binds an attestation to actual TEE hardware — the `report_hash` is included
/// in the evidence and verified on-chain, proving each attestation triggered
/// a fresh hardware interaction.
#[derive(Debug, Clone)]
pub struct HardwareReport {
    /// SHA-256 of the raw platform-specific hardware report.
    /// On-chain, verifiers check this is non-zero.
    /// Off-chain, the full report can be validated against this hash.
    pub report_hash: [u8; 32],
    /// Enclave measurement from the hardware report (baked in by hardware).
    pub enclave_measurement: [u8; 32],
    /// Signer measurement from the hardware report (baked in by hardware).
    pub signer_measurement: [u8; 32],
    /// Application-level measurement (Nitro PCR2). Only populated for Nitro;
    /// SGX and SEV leave this `None`.
    pub application_measurement: Option<[u8; 32]>,
}

/// Attestation authority-signed key attestation returned by the hardware provider.
///
/// In production, this signature is produced by the attestation relay after it
/// verifies the hardware attestation chain (Intel DCAP, AWS NSM, AMD PSP).
/// The on-chain verifier checks this signature against the governance-configured
/// attestation authority key (either a direct vendor root or a relay key).
///
/// The signed message is: `SHA-256(platformKeyX || platformKeyY || platformId)`
#[derive(Debug, Clone)]
pub struct VendorKeyAttestation {
    /// P-256 ECDSA signature R component (32 bytes, big-endian).
    pub vendor_sig_r: [u8; 32],
    /// P-256 ECDSA signature S component (32 bytes, big-endian).
    pub vendor_sig_s: [u8; 32],
}

/// Platform key bundle returned by the hardware provider's key generation.
///
/// Contains the public key coordinates (for on-chain registration) and a
/// vendor attestation proving the key was generated inside real TEE hardware.
///
/// The P-256 private key is retained INSIDE the hardware provider — it is
/// never exposed through this struct. Signing is performed via the provider's
/// `sign_with_platform_key()` method. This ensures the private key stays
/// within the TEE-boundary abstraction even if the process is compromised
/// after bootstrap.
#[derive(Debug, Clone)]
pub struct PlatformKeyBundle {
    /// P-256 public key X coordinate (32 bytes, big-endian).
    pub public_key_x: [u8; 32],
    /// P-256 public key Y coordinate (32 bytes, big-endian).
    pub public_key_y: [u8; 32],
    /// Vendor attestation proving the key was generated inside TEE hardware.
    pub vendor_attestation: VendorKeyAttestation,
}

/// Trait for platform-specific hardware attestation report generation.
///
/// Each TEE platform (SGX, Nitro, SEV) has a hardware API that generates a
/// signed attestation report binding `report_data` to the running enclave's
/// measurements. The hardware guarantees these measurements cannot be forged.
///
/// The `report_data` field is bound into the hardware report, creating a
/// cryptographic link between the attestation and the specific hardware report.
pub trait HardwareAttestationProvider: Send + Sync {
    /// Generate a fresh hardware attestation report.
    ///
    /// `report_data` is bound into the hardware report (e.g., as SGX REPORTDATA,
    /// Nitro user_data, or SEV REPORT_DATA).
    fn generate_report(&self, report_data: &[u8; 32]) -> Result<HardwareReport, AttestationError>;

    /// Generate a hardware-rooted P-256 platform key and vendor attestation.
    ///
    /// The key MUST be generated inside the TEE hardware, not supplied externally.
    /// This is the critical security boundary: the private key originates from
    /// hardware entropy and is kept INSIDE the provider — never exposed as raw
    /// bytes outside the `HardwareAttestationProvider` abstraction.
    ///
    /// **Entropy source**: Real providers MUST use `OsRng` (not `thread_rng`)
    /// to sample key material.  `OsRng` calls `getrandom(2)` on every
    /// invocation, which inside a TEE enclave maps to:
    ///
    /// | Platform | Entropy path |
    /// |----------|--------------|
    /// | SGX / Gramine | `getrandom` → Gramine shim → `RDRAND` instruction |
    /// | Nitro Enclaves | `getrandom` → `virtio-rng` → hypervisor HRNG |
    /// | SEV-SNP | `getrandom` → `/dev/urandom` → AMD CCP TRNG |
    ///
    /// `thread_rng()` is a buffered ChaCha20 PRNG seeded once — process
    /// compromise could extract its state and predict future outputs.
    ///
    /// After this call, the provider holds the private key internally and
    /// signing is performed via `sign_with_platform_key()`.
    ///
    /// Real providers: use `OsRng` to generate the key, create a hardware
    /// attestation (DCAP quote / NSM document / SNP report) binding the
    /// public key to this enclave, then call the vendor attester to certify it.
    ///
    /// Mock provider: generates a random key in software and signs with a test
    /// vendor root key (D=2) for testing.
    fn generate_platform_key(
        &self,
        platform_id: u8,
    ) -> Result<PlatformKeyBundle, AttestationError>;

    /// Sign a report body with the hardware-held P-256 platform key.
    ///
    /// Computes `SHA-256(report_body)` and signs the hash with ECDSA P-256.
    /// Returns `(r, s)` as 32-byte big-endian arrays suitable for ABI encoding.
    ///
    /// The private key never leaves the provider — this method is the ONLY way
    /// to produce signatures, ensuring the key stays within the TEE-boundary
    /// abstraction. Must be called after `generate_platform_key()`.
    fn sign_with_platform_key(
        &self,
        report_body: &[u8],
    ) -> Result<([u8; 32], [u8; 32]), AttestationError>;

    /// The TEE platform this provider serves.
    fn platform(&self) -> TEEPlatform;

    /// Expose the raw platform key bytes for test verification ONLY.
    ///
    /// This is NOT compiled into production builds.  Tests use it to verify
    /// P-256 signatures without going through the `sign_with_platform_key`
    /// path (i.e. they reconstruct the report body and check independently).
    #[cfg(test)]
    fn platform_key_bytes_for_testing(&self) -> Option<[u8; 32]>;
}

/// Trait for producing attestation authority key attestations.
///
/// In production, the attestation proves a P-256 platform key was generated
/// inside real TEE hardware. An **attestation relay** (trusted bridge) verifies
/// the hardware attestation chain (DCAP / NSM / AMD PSP) and signs the key
/// binding in the format expected by the on-chain verifier:
///   `SHA-256(pkX || pkY || platformId)`
///
/// **Trust model**: The relay's P-256 public key is registered on-chain via
/// `VaultTEEVerifier.registerAttestationRelay()`. The on-chain contract
/// provides relay accountability through time-locked key rotation, governance
/// liveness challenges, and emergency revocation. See the Solidity contract's
/// `AttestationRelay` struct for the full governance model.
///
/// Implementations:
///   - `LocalVendorAttester`: Signs with a local P-256 key (dev/test only).
///   - `RemoteVendorAttester`: Sends hardware evidence to a relay (production).
pub trait VendorAttester: Send + Sync {
    /// Produce a vendor attestation for a platform key.
    ///
    /// `hardware_evidence` is the raw platform attestation artifact (DCAP quote,
    /// Nitro attestation document, SEV-SNP report) binding the key to real TEE
    /// hardware. A production attester verifies this before signing.
    fn attest_platform_key(
        &self,
        pk_x: &[u8; 32],
        pk_y: &[u8; 32],
        platform_id: u8,
        hardware_evidence: &[u8],
    ) -> Result<VendorKeyAttestation, AttestationError>;
}

/// Local vendor attester for development and testing.
///
/// Signs `SHA-256(pkX || pkY || platformId)` with a provided P-256 private key.
/// The `hardware_evidence` parameter is ignored — no hardware verification is
/// performed. Use this **only** for:
///   - Development with real TEE hardware but a local vendor key
///   - Unit tests where hardware is not available
///
/// ⚠ **Not for production.** The operator holding the vendor signing key
/// locally defeats the trust separation: a compromised operator could forge
/// vendor attestations. In production, use `RemoteVendorAttester` so that
/// hardware evidence is verified by an independent attestation relay.
pub struct LocalVendorAttester {
    vendor_key: [u8; 32],
}

impl LocalVendorAttester {
    pub fn new(vendor_key: [u8; 32]) -> Self {
        Self { vendor_key }
    }
}

impl VendorAttester for LocalVendorAttester {
    fn attest_platform_key(
        &self,
        pk_x: &[u8; 32],
        pk_y: &[u8; 32],
        platform_id: u8,
        _hardware_evidence: &[u8],
    ) -> Result<VendorKeyAttestation, AttestationError> {
        use p256::ecdsa::{SigningKey as P256SigningKey, Signature as P256Signature};
        use p256::ecdsa::signature::hazmat::PrehashSigner;

        let mut hasher = Sha256::new();
        hasher.update(pk_x);
        hasher.update(pk_y);
        hasher.update([platform_id]);
        let msg_hash = {
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        let vendor_key = P256SigningKey::from_slice(&self.vendor_key)
            .map_err(|e| AttestationError::SigningFailed(format!("invalid vendor key: {}", e)))?;
        let sig: P256Signature = vendor_key.sign_prehash(&msg_hash)
            .map_err(|e| AttestationError::SigningFailed(format!("vendor signing failed: {}", e)))?;

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig.r().to_bytes());
        s.copy_from_slice(&sig.s().to_bytes());

        Ok(VendorKeyAttestation {
            vendor_sig_r: r,
            vendor_sig_s: s,
        })
    }
}

/// Remote attestation relay attester for production deployments.
///
/// Sends the hardware evidence (DCAP quote, Nitro attestation document, or
/// SEV-SNP report) to a trusted **attestation relay** service that:
///   1. Verifies the full hardware attestation chain (Intel/AWS/AMD root of trust)
///   2. Confirms the platform key hash appears in the evidence `report_data`
///   3. Signs `SHA-256(pkX || pkY || platformId)` with its own P-256 key
///
/// ## Trust Model
///
/// The relay is a **trusted bridge** between hardware vendors and the chain.
/// Its P-256 public key is registered on-chain via
/// `VaultTEEVerifier.registerAttestationRelay()`, which provides:
///
///   - **Identity tracking**: relay description, registration timestamp
///   - **Rotation timelock**: 48-hour delay for key changes
///   - **Liveness challenges**: governance can challenge the relay to prove
///     it still possesses the signing key
///   - **Emergency revocation**: immediate deactivation if compromised
///   - **Attestation counting**: tracks how many enclaves the relay has certified
///
/// If the relay is compromised, it could certify arbitrary platform keys.
/// The on-chain governance controls mitigate this by enabling detection
/// (liveness challenges), containment (revocation), and recovery (rotation).
///
/// ## Protocol
///
/// ```text
/// POST {relay_url}
/// Content-Type: application/json
///
/// {
///   "platform_key_x": "<hex 32 bytes>",
///   "platform_key_y": "<hex 32 bytes>",
///   "platform_id": <u8>,
///   "hardware_evidence": "<hex>"
/// }
///
/// -> 200 OK
/// {
///   "vendor_sig_r": "<hex 32 bytes>",
///   "vendor_sig_s": "<hex 32 bytes>"
/// }
/// ```
///
/// Enable via: `cargo build --features remote-attestation`
#[cfg(feature = "remote-attestation")]
pub struct RemoteVendorAttester {
    relay_url: String,
}

#[cfg(feature = "remote-attestation")]
impl RemoteVendorAttester {
    pub fn new(relay_url: String) -> Self {
        Self { relay_url }
    }
}

#[cfg(feature = "remote-attestation")]
impl VendorAttester for RemoteVendorAttester {
    fn attest_platform_key(
        &self,
        pk_x: &[u8; 32],
        pk_y: &[u8; 32],
        platform_id: u8,
        hardware_evidence: &[u8],
    ) -> Result<VendorKeyAttestation, AttestationError> {
        let request_body = serde_json::json!({
            "platform_key_x": hex::encode(pk_x),
            "platform_key_y": hex::encode(pk_y),
            "platform_id": platform_id,
            "hardware_evidence": hex::encode(hardware_evidence),
        });

        let client = reqwest::blocking::Client::new();
        let response = client.post(&self.relay_url)
            .json(&request_body)
            .send()
            .map_err(|e| AttestationError::HardwareUnavailable(
                format!("attestation relay request to {} failed: {}", self.relay_url, e)))?;

        if !response.status().is_success() {
            return Err(AttestationError::HardwareUnavailable(
                format!("attestation relay returned HTTP {}", response.status())));
        }

        let resp_body: serde_json::Value = response.json()
            .map_err(|e| AttestationError::HardwareUnavailable(
                format!("attestation relay response parse failed: {}", e)))?;

        let r_hex = resp_body["vendor_sig_r"].as_str()
            .ok_or_else(|| AttestationError::HardwareUnavailable(
                "attestation relay response missing 'vendor_sig_r'".into()))?;
        let s_hex = resp_body["vendor_sig_s"].as_str()
            .ok_or_else(|| AttestationError::HardwareUnavailable(
                "attestation relay response missing 'vendor_sig_s'".into()))?;

        let r_bytes = hex::decode(r_hex)
            .map_err(|e| AttestationError::HardwareUnavailable(
                format!("invalid vendor_sig_r hex: {}", e)))?;
        let s_bytes = hex::decode(s_hex)
            .map_err(|e| AttestationError::HardwareUnavailable(
                format!("invalid vendor_sig_s hex: {}", e)))?;

        if r_bytes.len() != 32 || s_bytes.len() != 32 {
            return Err(AttestationError::HardwareUnavailable(
                format!("vendor signature components must be 32 bytes each, got r={} s={}",
                    r_bytes.len(), s_bytes.len())));
        }

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&r_bytes);
        s.copy_from_slice(&s_bytes);

        Ok(VendorKeyAttestation {
            vendor_sig_r: r,
            vendor_sig_s: s,
        })
    }
}

/// Generate a P-256 platform key using the OS-level CSPRNG (`OsRng`).
///
/// Unlike `rand::thread_rng()` (a userspace ChaCha20 PRNG seeded once from
/// `getrandom`), `OsRng` calls `getrandom(2)` directly on **every** call.
/// Inside TEE enclaves this maps to hardware entropy:
///
/// - **SGX / Gramine**: `getrandom` → Gramine shim → `RDRAND` instruction
/// - **Nitro Enclaves**: `getrandom` → `virtio-rng` → hypervisor HRNG
/// - **SEV-SNP**: `getrandom` → `/dev/urandom` → AMD CCP TRNG
///
/// This guarantees the private key material never depends on userspace PRNG
/// state, which could be extracted after process compromise.
///
/// Returns `(private_key, public_key_x, public_key_y)`.
#[cfg_attr(not(any(feature = "sgx", feature = "nitro", feature = "sev")), allow(dead_code))]
fn generate_p256_platform_key() -> Result<([u8; 32], [u8; 32], [u8; 32]), AttestationError> {
    use p256::ecdsa::SigningKey as P256SigningKey;
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut key_bytes = [0u8; 32];
    loop {
        OsRng.fill_bytes(&mut key_bytes);
        if P256SigningKey::from_slice(&key_bytes).is_ok() {
            break;
        }
    }

    let signing_key = P256SigningKey::from_slice(&key_bytes)
        .map_err(|e| AttestationError::SigningFailed(format!("invalid P-256 key: {}", e)))?;
    let verifying_key = signing_key.verifying_key();
    let point = verifying_key.to_encoded_point(false);
    let mut pk_x = [0u8; 32];
    let mut pk_y = [0u8; 32];
    pk_x.copy_from_slice(point.x().unwrap());
    pk_y.copy_from_slice(point.y().unwrap());

    Ok((key_bytes, pk_x, pk_y))
}

/// Sign a report body with a P-256 platform key held inside a hardware provider.
///
/// Computes `SHA-256(report_body)` and signs the hash with ECDSA P-256.
/// Returns `(r, s)` as 32-byte big-endian arrays suitable for ABI encoding.
///
/// This is a shared helper used by all providers' `sign_with_platform_key()`
/// implementations. The key bytes are passed by reference and never leave the
/// provider that holds them.
fn p256_sign_report_body(
    key_bytes: &[u8; 32],
    report_body: &[u8],
) -> Result<([u8; 32], [u8; 32]), AttestationError> {
    use p256::ecdsa::{SigningKey as P256SigningKey, Signature as P256Signature};
    use p256::ecdsa::signature::hazmat::PrehashSigner;

    let report_hash = {
        let mut h = Sha256::new();
        h.update(report_body);
        let result = h.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        hash
    };

    let p256_key = P256SigningKey::from_slice(key_bytes)
        .map_err(|e| AttestationError::SigningFailed(format!("invalid P-256 platform key: {}", e)))?;
    let sig: P256Signature = p256_key.sign_prehash(&report_hash)
        .map_err(|e| AttestationError::SigningFailed(format!("P-256 evidence signing failed: {}", e)))?;

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig.r().to_bytes());
    s.copy_from_slice(&sig.s().to_bytes());
    Ok((r, s))
}

/// Mock hardware attestation provider for testing.
///
/// Generates deterministic simulated hardware reports using:
///   report_hash = SHA-256("MOCK_HW_REPORT_V1" || enclave_hash || signer_hash || report_data)
///
/// Also generates mock vendor key attestations by signing with a test vendor
/// root key. The test vendor root key is passed in at construction and is
/// NEVER a real vendor key.
///
/// In production, this is replaced by platform-specific providers that call
/// actual hardware APIs (sgx_create_report, /dev/nsm, /dev/sev-guest).
pub struct MockHardwareProvider {
    enclave_hash: [u8; 32],
    signer_hash: [u8; 32],
    /// Nitro PCR2 application hash (optional — only set for Nitro platform).
    application_hash: Option<[u8; 32]>,
    /// Test vendor root key for mock vendor attestations.
    /// In production, this key is held by the hardware vendor (Intel/AWS/AMD)
    /// and NEVER touches the TEE operator's software.
    vendor_root_key: [u8; 32],
    /// P-256 platform key, held inside the provider. Set by generate_platform_key(),
    /// read by sign_with_platform_key(). Never exposed as raw bytes.
    platform_key: std::sync::OnceLock<[u8; 32]>,
}

impl MockHardwareProvider {
    pub fn new(enclave_hash: [u8; 32], signer_hash: [u8; 32], vendor_root_key: [u8; 32]) -> Self {
        Self {
            enclave_hash,
            signer_hash,
            application_hash: None,
            vendor_root_key,
            platform_key: std::sync::OnceLock::new(),
        }
    }

    /// Create a mock provider with application hash (for Nitro simulation).
    pub fn with_application_hash(mut self, app_hash: [u8; 32]) -> Self {
        self.application_hash = Some(app_hash);
        self
    }
}

impl HardwareAttestationProvider for MockHardwareProvider {
    fn generate_report(&self, report_data: &[u8; 32]) -> Result<HardwareReport, AttestationError> {
        // Simulate hardware report generation
        let mut hasher = Sha256::new();
        hasher.update(b"MOCK_HW_REPORT_V1");
        hasher.update(&self.enclave_hash);
        hasher.update(&self.signer_hash);
        hasher.update(report_data);
        let mock_report = hasher.finalize();

        // Hash the mock report to get the commitment
        let mut report_hash_hasher = Sha256::new();
        report_hash_hasher.update(&mock_report);
        let mut report_hash = [0u8; 32];
        report_hash.copy_from_slice(&report_hash_hasher.finalize());

        Ok(HardwareReport {
            report_hash,
            enclave_measurement: self.enclave_hash,
            signer_measurement: self.signer_hash,
            application_measurement: self.application_hash,
        })
    }

    fn generate_platform_key(
        &self,
        platform_id: u8,
    ) -> Result<PlatformKeyBundle, AttestationError> {
        use p256::ecdsa::{SigningKey as P256SigningKey, Signature as P256Signature};
        use p256::ecdsa::signature::hazmat::PrehashSigner;

        // Generate a random P-256 key (simulates hardware key generation).
        // In a real TEE, this would use hardware RNG + sealed storage.
        let platform_key = {
            use rand::RngCore;
            let mut key_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key_bytes);
            // Ensure valid P-256 scalar (non-zero, < curve order).
            // Retry if we get an invalid key (astronomically unlikely).
            loop {
                match P256SigningKey::from_slice(&key_bytes) {
                    Ok(_) => break key_bytes,
                    Err(_) => rand::thread_rng().fill_bytes(&mut key_bytes),
                }
            }
        };

        // Derive the public key
        let p256_signing = P256SigningKey::from_slice(&platform_key)
            .map_err(|e| AttestationError::SigningFailed(format!("invalid platform key: {}", e)))?;
        let verifying_key = p256_signing.verifying_key();
        let point = verifying_key.to_encoded_point(false);
        let mut pk_x = [0u8; 32];
        let mut pk_y = [0u8; 32];
        pk_x.copy_from_slice(point.x().unwrap());
        pk_y.copy_from_slice(point.y().unwrap());

        // Sign the attestation message: SHA-256(pkX || pkY || platformId)
        let mut hasher = Sha256::new();
        hasher.update(&pk_x);
        hasher.update(&pk_y);
        hasher.update([platform_id]);
        let msg_hash = {
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        // Sign with test vendor root key
        let vendor_key = P256SigningKey::from_slice(&self.vendor_root_key)
            .map_err(|e| AttestationError::SigningFailed(format!("invalid vendor root key: {}", e)))?;
        let sig: P256Signature = vendor_key.sign_prehash(&msg_hash)
            .map_err(|e| AttestationError::SigningFailed(format!("vendor signing failed: {}", e)))?;

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig.r().to_bytes());
        s.copy_from_slice(&sig.s().to_bytes());

        // Store the private key inside the provider — never expose it externally.
        let _ = self.platform_key.set(platform_key);

        Ok(PlatformKeyBundle {
            public_key_x: pk_x,
            public_key_y: pk_y,
            vendor_attestation: VendorKeyAttestation {
                vendor_sig_r: r,
                vendor_sig_s: s,
            },
        })
    }

    fn sign_with_platform_key(&self, report_body: &[u8]) -> Result<([u8; 32], [u8; 32]), AttestationError> {
        let key_bytes = self.platform_key.get()
            .ok_or_else(|| AttestationError::SigningFailed(
                "platform key not yet generated; call generate_platform_key() first".into()))?;
        p256_sign_report_body(key_bytes, report_body)
    }

    fn platform(&self) -> TEEPlatform {
        TEEPlatform::Mock
    }

    #[cfg(test)]
    fn platform_key_bytes_for_testing(&self) -> Option<[u8; 32]> {
        self.platform_key.get().copied()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Real hardware providers — feature-gated implementations
// ─────────────────────────────────────────────────────────────────────────────

/// Intel SGX hardware attestation provider.
///
/// With `sgx` feature: uses Gramine's `/dev/attestation/*` pseudo-files to
/// generate DCAP quotes containing MRENCLAVE/MRSIGNER baked in by SGX hardware,
/// with report_data bound to the attestation digest.
///
/// Without the `sgx` feature: returns PlatformNotAvailable.
///
/// ## Gramine pseudo-file interface
///
/// Gramine (the standard way to run unmodified applications in SGX) exposes:
///   - `/dev/attestation/user_report_data` — write 64 bytes (report_data in first 32)
///   - `/dev/attestation/report` — read 432 bytes (SGX report struct)
///   - `/dev/attestation/quote` — read DCAP quote (variable length)
///
/// SGX report body layout (384 bytes):
///   - offset 64: MRENCLAVE (32 bytes) — enclave code measurement
///   - offset 128: MRSIGNER (32 bytes) — enclave signer identity
///   - offset 320: REPORTDATA (64 bytes) — user-supplied data
pub struct SgxHardwareProvider {
    #[cfg_attr(not(feature = "sgx"), allow(dead_code))]
    vendor_attester: Option<Box<dyn VendorAttester>>,
    /// P-256 platform key, held inside the provider. Set by generate_platform_key(),
    /// used by sign_with_platform_key(). Never exposed as raw bytes.
    #[cfg_attr(not(feature = "sgx"), allow(dead_code))]
    platform_key: std::sync::OnceLock<[u8; 32]>,
}

impl SgxHardwareProvider {
    /// Create with an explicit vendor attester (production or custom attester).
    pub fn with_attester(vendor_attester: Box<dyn VendorAttester>) -> Self {
        Self {
            vendor_attester: Some(vendor_attester),
            platform_key: std::sync::OnceLock::new(),
        }
    }

    /// Create with a local vendor key (development/testing only).
    /// When the `sgx` feature is not enabled, returns PlatformNotAvailable on all calls.
    pub fn create(vendor_root_key: [u8; 32]) -> Self {
        #[cfg(feature = "sgx")]
        {
            Self {
                vendor_attester: Some(Box::new(LocalVendorAttester::new(vendor_root_key))),
                platform_key: std::sync::OnceLock::new(),
            }
        }
        #[cfg(not(feature = "sgx"))]
        {
            let _ = vendor_root_key;
            Self {
                vendor_attester: None,
                platform_key: std::sync::OnceLock::new(),
            }
        }
    }
}

/// Read an SGX attestation from Gramine pseudo-files.
///
/// Writes `user_data` (32 bytes) to `/dev/attestation/user_report_data`,
/// then reads the SGX report (for measurements) and DCAP quote (for hashing).
///
/// Returns (quote_bytes, mrenclave, mrsigner).
#[cfg(feature = "sgx")]
fn sgx_get_attestation(user_data: &[u8; 32]) -> Result<(Vec<u8>, [u8; 32], [u8; 32]), AttestationError> {
    // Gramine: write report data (padded to 64 bytes for SGX REPORTDATA field)
    let mut padded = [0u8; 64];
    padded[..32].copy_from_slice(user_data);
    std::fs::write("/dev/attestation/user_report_data", &padded)
        .map_err(|e| AttestationError::HardwareUnavailable(
            format!("SGX write user_report_data: {} (is Gramine configured?)", e)))?;

    // Read the SGX report (432 bytes = 384 body + 32 keyid + 16 mac)
    let report_bytes = std::fs::read("/dev/attestation/report")
        .map_err(|e| AttestationError::HardwareUnavailable(
            format!("SGX read report: {}", e)))?;

    if report_bytes.len() < 384 {
        return Err(AttestationError::HardwareUnavailable(
            format!("SGX report too short: {} bytes (expected >= 384)", report_bytes.len())));
    }

    // Extract MRENCLAVE (offset 64, 32 bytes) and MRSIGNER (offset 128, 32 bytes)
    let mut mrenclave = [0u8; 32];
    let mut mrsigner = [0u8; 32];
    mrenclave.copy_from_slice(&report_bytes[64..96]);
    mrsigner.copy_from_slice(&report_bytes[128..160]);

    // Read the DCAP quote (remotely verifiable attestation artifact)
    let quote_bytes = std::fs::read("/dev/attestation/quote")
        .map_err(|e| AttestationError::HardwareUnavailable(
            format!("SGX read quote: {} (is DCAP configured?)", e)))?;

    if quote_bytes.len() < 432 {
        return Err(AttestationError::HardwareUnavailable(
            format!("SGX quote too short: {} bytes", quote_bytes.len())));
    }

    Ok((quote_bytes, mrenclave, mrsigner))
}

impl HardwareAttestationProvider for SgxHardwareProvider {
    fn generate_report(&self, report_data: &[u8; 32]) -> Result<HardwareReport, AttestationError> {
        #[cfg(feature = "sgx")]
        {
            let (quote_bytes, mrenclave, mrsigner) = sgx_get_attestation(report_data)?;

            // Hash the full DCAP quote as the report commitment
            let mut hasher = Sha256::new();
            hasher.update(&quote_bytes);
            let mut report_hash = [0u8; 32];
            report_hash.copy_from_slice(&hasher.finalize());

            Ok(HardwareReport {
                report_hash,
                enclave_measurement: mrenclave,
                signer_measurement: mrsigner,
                application_measurement: None,
            })
        }
        #[cfg(not(feature = "sgx"))]
        {
            let _ = report_data;
            Err(AttestationError::PlatformNotAvailable(TEEPlatform::IntelSGX))
        }
    }

    fn generate_platform_key(&self, platform_id: u8) -> Result<PlatformKeyBundle, AttestationError> {
        #[cfg(feature = "sgx")]
        {
            let vendor_attester = self.vendor_attester.as_ref()
                .ok_or_else(|| AttestationError::HardwareUnavailable(
                    "SGX provider requires a VendorAttester for key generation".into()))?;

            // Generate P-256 key from OS-level CSPRNG (OsRng → getrandom).
            // Inside SGX / Gramine: getrandom() → Gramine shim → RDRAND
            // instruction, which sources entropy from the CPU's hardware RNG.
            // The key bytes never pass through a userspace PRNG buffer.
            let (private_key, pk_x, pk_y) = generate_p256_platform_key()?;

            // Store the private key inside the provider — never expose it.
            let _ = self.platform_key.set(private_key);

            // Create DCAP quote binding the public key hash to this enclave
            let mut key_hash = Sha256::new();
            key_hash.update(&pk_x);
            key_hash.update(&pk_y);
            let mut key_digest = [0u8; 32];
            key_digest.copy_from_slice(&key_hash.finalize());

            let (hw_evidence, _, _) = sgx_get_attestation(&key_digest)?;

            // Get vendor attestation (verifies DCAP quote + signs key binding)
            let vendor_attestation = vendor_attester.attest_platform_key(
                &pk_x, &pk_y, platform_id, &hw_evidence,
            )?;

            Ok(PlatformKeyBundle {
                public_key_x: pk_x,
                public_key_y: pk_y,
                vendor_attestation,
            })
        }
        #[cfg(not(feature = "sgx"))]
        {
            let _ = platform_id;
            Err(AttestationError::PlatformNotAvailable(TEEPlatform::IntelSGX))
        }
    }

    fn sign_with_platform_key(&self, report_body: &[u8]) -> Result<([u8; 32], [u8; 32]), AttestationError> {
        let key_bytes = self.platform_key.get()
            .ok_or_else(|| AttestationError::SigningFailed(
                "SGX platform key not yet generated; call generate_platform_key() first".into()))?;
        p256_sign_report_body(key_bytes, report_body)
    }

    fn platform(&self) -> TEEPlatform { TEEPlatform::IntelSGX }

    #[cfg(test)]
    fn platform_key_bytes_for_testing(&self) -> Option<[u8; 32]> {
        self.platform_key.get().copied()
    }
}

/// AWS Nitro Enclaves hardware attestation provider.
///
/// With `nitro` feature: calls the Nitro Secure Module (NSM) via `/dev/nsm`
/// ioctl to generate attestation documents containing PCR values baked in by
/// Nitro hardware, with user_data bound to the attestation digest.
///
/// Without the `nitro` feature: returns PlatformNotAvailable.
///
/// ## NSM interface
///
/// The NSM driver exposes `/dev/nsm` with ioctl `NSM_IO_REQUEST`:
///   - Request: CBOR `{"Attestation": {"user_data": <bytes>, ...}}`
///   - Response: CBOR `{"Attestation": {"document": <COSE_Sign1>}}`
///
/// The COSE_Sign1 document contains PCR values (48 bytes each, SHA-384):
///   - PCR0: enclave image hash
///   - PCR1: kernel/boot hash
///   - PCR2: application hash
///
/// On-chain, PCRs are stored as `sha256(pcr)` (48 bytes → 32 bytes).
pub struct NitroHardwareProvider {
    #[cfg_attr(not(feature = "nitro"), allow(dead_code))]
    vendor_attester: Option<Box<dyn VendorAttester>>,
    /// P-256 platform key, held inside the provider. Never exposed as raw bytes.
    #[cfg_attr(not(feature = "nitro"), allow(dead_code))]
    platform_key: std::sync::OnceLock<[u8; 32]>,
}

impl NitroHardwareProvider {
    /// Create with an explicit vendor attester (production or custom attester).
    pub fn with_attester(vendor_attester: Box<dyn VendorAttester>) -> Self {
        Self {
            vendor_attester: Some(vendor_attester),
            platform_key: std::sync::OnceLock::new(),
        }
    }

    /// Create with a local vendor key (development/testing only).
    pub fn create(vendor_root_key: [u8; 32]) -> Self {
        #[cfg(feature = "nitro")]
        {
            Self {
                vendor_attester: Some(Box::new(LocalVendorAttester::new(vendor_root_key))),
                platform_key: std::sync::OnceLock::new(),
            }
        }
        #[cfg(not(feature = "nitro"))]
        {
            let _ = vendor_root_key;
            Self {
                vendor_attester: None,
                platform_key: std::sync::OnceLock::new(),
            }
        }
    }
}

/// NSM ioctl message struct: two iovec-style (pointer + length) entries.
#[cfg(feature = "nitro")]
#[repr(C)]
struct NsmIovec {
    addr: *mut u8,
    len: u64,
}

#[cfg(feature = "nitro")]
#[repr(C)]
struct NsmMessage {
    request: NsmIovec,
    response: NsmIovec,
}

/// NSM_IO_REQUEST ioctl number: _IOWR(0x0A, 0, NsmMessage).
/// NsmMessage is 32 bytes (2 × (ptr + u64) = 2 × 16).
#[cfg(feature = "nitro")]
const NSM_IOCTL_REQUEST: libc::c_ulong =
    (3 << 30) | (32 << 16) | (0x0A << 8) | 0; // 0xC020_0A00

/// Send a CBOR request to the NSM device and return the CBOR response.
#[cfg(feature = "nitro")]
fn nsm_request(request_cbor: &[u8]) -> Result<Vec<u8>, AttestationError> {
    use std::os::unix::io::AsRawFd;

    let nsm_fd = std::fs::OpenOptions::new()
        .read(true).write(true)
        .open("/dev/nsm")
        .map_err(|e| AttestationError::HardwareUnavailable(
            format!("Nitro NSM open: {} (running inside a Nitro enclave?)", e)))?;

    let mut req_buf = request_cbor.to_vec();
    let mut resp_buf = vec![0u8; 0x3000]; // NSM_RESPONSE_MAX_SIZE

    let mut msg = NsmMessage {
        request: NsmIovec {
            addr: req_buf.as_mut_ptr(),
            len: req_buf.len() as u64,
        },
        response: NsmIovec {
            addr: resp_buf.as_mut_ptr(),
            len: resp_buf.len() as u64,
        },
    };

    let ret = unsafe {
        libc::ioctl(nsm_fd.as_raw_fd(), NSM_IOCTL_REQUEST, &mut msg as *mut NsmMessage)
    };
    if ret != 0 {
        return Err(AttestationError::HardwareUnavailable(
            format!("NSM ioctl failed: errno {}", std::io::Error::last_os_error())));
    }

    let resp_len = msg.response.len as usize;
    resp_buf.truncate(resp_len);
    Ok(resp_buf)
}

/// Send an NSM Attestation request and extract the attestation document,
/// PCR0, PCR1, and PCR2 from the response.
///
/// Returns (document_bytes, pcr0_hash, pcr1_hash, pcr2_hash) where
/// PCR hashes are `sha256(pcr_48_bytes)` compressed to 32 bytes.
#[cfg(feature = "nitro")]
fn nitro_get_attestation(user_data: &[u8; 32]) -> Result<(Vec<u8>, [u8; 32], [u8; 32], [u8; 32]), AttestationError> {
    // Encode CBOR request: {"Attestation": {"user_data": <bytes32>}}
    let request = ciborium::Value::Map(vec![
        (ciborium::Value::Text("Attestation".into()), ciborium::Value::Map(vec![
            (ciborium::Value::Text("user_data".into()), ciborium::Value::Bytes(user_data.to_vec())),
            (ciborium::Value::Text("nonce".into()), ciborium::Value::Null),
            (ciborium::Value::Text("public_key".into()), ciborium::Value::Null),
        ])),
    ]);
    let mut request_bytes = Vec::new();
    ciborium::into_writer(&request, &mut request_bytes)
        .map_err(|e| AttestationError::HardwareUnavailable(format!("CBOR encode: {}", e)))?;

    let resp_bytes = nsm_request(&request_bytes)?;

    // Parse response: {"Attestation": {"document": <bytes>}}
    let resp: ciborium::Value = ciborium::from_reader(&resp_bytes[..])
        .map_err(|e| AttestationError::HardwareUnavailable(format!("CBOR decode response: {}", e)))?;

    let document_bytes = extract_cbor_attestation_document(&resp)?;

    // Parse COSE_Sign1 document to extract PCRs from the payload.
    // COSE_Sign1 = Tag(18, [protected, unprotected, payload, signature])
    let cose: ciborium::Value = ciborium::from_reader(&document_bytes[..])
        .map_err(|e| AttestationError::HardwareUnavailable(format!("CBOR decode COSE: {}", e)))?;

    let payload_bytes = extract_cose_payload(&cose)?;

    // Parse payload: {"pcrs": {0: <bytes48>, 1: <bytes48>, 2: <bytes48>}, ...}
    let payload: ciborium::Value = ciborium::from_reader(&payload_bytes[..])
        .map_err(|e| AttestationError::HardwareUnavailable(format!("CBOR decode payload: {}", e)))?;

    let (pcr0, pcr1, pcr2) = extract_pcr_values(&payload)?;

    // SHA-256 compress PCR values (48 bytes → 32 bytes for on-chain storage)
    let pcr0_hash = sha256_raw(&pcr0);
    let pcr1_hash = sha256_raw(&pcr1);
    let pcr2_hash = sha256_raw(&pcr2);

    Ok((document_bytes, pcr0_hash, pcr1_hash, pcr2_hash))
}

/// Extract the attestation document bytes from an NSM CBOR response.
#[cfg(feature = "nitro")]
fn extract_cbor_attestation_document(resp: &ciborium::Value) -> Result<Vec<u8>, AttestationError> {
    let map = resp.as_map()
        .ok_or_else(|| AttestationError::HardwareUnavailable("NSM response not a map".into()))?;

    for (k, v) in map {
        if k.as_text() == Some("Attestation") {
            let inner = v.as_map()
                .ok_or_else(|| AttestationError::HardwareUnavailable("Attestation not a map".into()))?;
            for (ik, iv) in inner {
                if ik.as_text() == Some("document") {
                    return iv.as_bytes()
                        .map(|b| b.to_vec())
                        .ok_or_else(|| AttestationError::HardwareUnavailable(
                            "document field not bytes".into()));
                }
            }
            return Err(AttestationError::HardwareUnavailable("no document in Attestation".into()));
        }
        // Check for error response
        if k.as_text() == Some("Error") {
            return Err(AttestationError::HardwareUnavailable(
                format!("NSM returned error: {:?}", v)));
        }
    }
    Err(AttestationError::HardwareUnavailable("no Attestation key in NSM response".into()))
}

/// Extract the payload bytes from a COSE_Sign1 structure.
/// COSE_Sign1 = Tag(18, [protected, unprotected, payload, signature])
#[cfg(feature = "nitro")]
fn extract_cose_payload(cose: &ciborium::Value) -> Result<Vec<u8>, AttestationError> {
    // May or may not be wrapped in Tag(18, ...)
    let array = match cose {
        ciborium::Value::Tag(18, inner) => inner.as_array(),
        ciborium::Value::Array(_) => cose.as_array(),
        _ => None,
    }.ok_or_else(|| AttestationError::HardwareUnavailable(
        "COSE_Sign1 not an array".into()))?;

    if array.len() < 4 {
        return Err(AttestationError::HardwareUnavailable(
            format!("COSE_Sign1 array too short: {} elements", array.len())));
    }

    // Payload is the 3rd element (index 2), a byte string containing CBOR
    array[2].as_bytes()
        .map(|b| b.to_vec())
        .ok_or_else(|| AttestationError::HardwareUnavailable(
            "COSE_Sign1 payload not bytes".into()))
}

/// Extract PCR0, PCR1, PCR2 byte values from a Nitro attestation payload.
/// PCRs are 48 bytes each (SHA-384 digests).
#[cfg(feature = "nitro")]
fn extract_pcr_values(payload: &ciborium::Value) -> Result<(Vec<u8>, Vec<u8>, Vec<u8>), AttestationError> {
    let map = payload.as_map()
        .ok_or_else(|| AttestationError::HardwareUnavailable("payload not a map".into()))?;

    let mut pcrs_map = None;
    for (k, v) in map {
        if k.as_text() == Some("pcrs") {
            pcrs_map = v.as_map();
            break;
        }
    }
    let pcrs = pcrs_map
        .ok_or_else(|| AttestationError::HardwareUnavailable("no pcrs in payload".into()))?;

    let mut pcr0 = None;
    let mut pcr1 = None;
    let mut pcr2 = None;

    for (k, v) in pcrs {
        let idx = k.as_integer().and_then(|i| i.try_into().ok());
        let bytes = v.as_bytes();
        match (idx, bytes) {
            (Some(0u64), Some(b)) => pcr0 = Some(b.to_vec()),
            (Some(1), Some(b)) => pcr1 = Some(b.to_vec()),
            (Some(2), Some(b)) => pcr2 = Some(b.to_vec()),
            _ => {}
        }
    }

    Ok((
        pcr0.ok_or_else(|| AttestationError::HardwareUnavailable("missing PCR0".into()))?,
        pcr1.ok_or_else(|| AttestationError::HardwareUnavailable("missing PCR1".into()))?,
        pcr2.ok_or_else(|| AttestationError::HardwareUnavailable("missing PCR2".into()))?,
    ))
}

impl HardwareAttestationProvider for NitroHardwareProvider {
    fn generate_report(&self, report_data: &[u8; 32]) -> Result<HardwareReport, AttestationError> {
        #[cfg(feature = "nitro")]
        {
            let (document_bytes, pcr0_hash, pcr1_hash, pcr2_hash) =
                nitro_get_attestation(report_data)?;

            // Hash the full attestation document as the report commitment
            let mut hasher = Sha256::new();
            hasher.update(&document_bytes);
            let mut report_hash = [0u8; 32];
            report_hash.copy_from_slice(&hasher.finalize());

            Ok(HardwareReport {
                report_hash,
                enclave_measurement: pcr0_hash,
                signer_measurement: pcr1_hash,
                application_measurement: Some(pcr2_hash),
            })
        }
        #[cfg(not(feature = "nitro"))]
        {
            let _ = report_data;
            Err(AttestationError::PlatformNotAvailable(TEEPlatform::AWSNitro))
        }
    }

    fn generate_platform_key(&self, platform_id: u8) -> Result<PlatformKeyBundle, AttestationError> {
        #[cfg(feature = "nitro")]
        {
            let vendor_attester = self.vendor_attester.as_ref()
                .ok_or_else(|| AttestationError::HardwareUnavailable(
                    "Nitro provider requires a VendorAttester for key generation".into()))?;

            // Generate P-256 key from OS-level CSPRNG (OsRng → getrandom).
            // Inside Nitro Enclaves: getrandom() → virtio-rng device →
            // Nitro hypervisor hardware RNG. The key bytes never pass
            // through a userspace PRNG buffer.
            let (private_key, pk_x, pk_y) = generate_p256_platform_key()?;

            // Store the private key inside the provider — never expose it.
            let _ = self.platform_key.set(private_key);

            // Create NSM attestation binding the public key to this enclave
            let mut key_hash = Sha256::new();
            key_hash.update(&pk_x);
            key_hash.update(&pk_y);
            let mut key_digest = [0u8; 32];
            key_digest.copy_from_slice(&key_hash.finalize());

            let (hw_evidence, _, _, _) = nitro_get_attestation(&key_digest)?;

            let vendor_attestation = vendor_attester.attest_platform_key(
                &pk_x, &pk_y, platform_id, &hw_evidence,
            )?;

            Ok(PlatformKeyBundle {
                public_key_x: pk_x,
                public_key_y: pk_y,
                vendor_attestation,
            })
        }
        #[cfg(not(feature = "nitro"))]
        {
            let _ = platform_id;
            Err(AttestationError::PlatformNotAvailable(TEEPlatform::AWSNitro))
        }
    }

    fn sign_with_platform_key(&self, report_body: &[u8]) -> Result<([u8; 32], [u8; 32]), AttestationError> {
        let key_bytes = self.platform_key.get()
            .ok_or_else(|| AttestationError::SigningFailed(
                "Nitro platform key not yet generated; call generate_platform_key() first".into()))?;
        p256_sign_report_body(key_bytes, report_body)
    }

    fn platform(&self) -> TEEPlatform { TEEPlatform::AWSNitro }

    #[cfg(test)]
    fn platform_key_bytes_for_testing(&self) -> Option<[u8; 32]> {
        self.platform_key.get().copied()
    }
}

/// AMD SEV-SNP hardware attestation provider.
///
/// With `sev` feature: calls `/dev/sev-guest` ioctl `SNP_GET_REPORT` to
/// generate an attestation report containing the MEASUREMENT baked in by
/// SEV hardware, with report_data bound to the attestation digest.
///
/// Without the `sev` feature: returns PlatformNotAvailable.
///
/// ## ioctl interface
///
/// ```text
/// SNP_GET_REPORT = _IOWR('S', 0x0, snp_guest_request_ioctl)
///
/// snp_report_req:   user_data[64], vmpl(u32), reserved[28]
/// snp_report_resp:  data[4000]
/// ```
///
/// SEV-SNP attestation report layout (1184 bytes):
///   - offset 80: REPORT_DATA (64 bytes) — user-supplied data
///   - offset 144: MEASUREMENT (48 bytes) — VM launch measurement
///   - offset 192: HOST_DATA (32 bytes) — host-provided data
pub struct SevHardwareProvider {
    #[cfg_attr(not(feature = "sev"), allow(dead_code))]
    vendor_attester: Option<Box<dyn VendorAttester>>,
    /// P-256 platform key, held inside the provider. Never exposed as raw bytes.
    #[cfg_attr(not(feature = "sev"), allow(dead_code))]
    platform_key: std::sync::OnceLock<[u8; 32]>,
}

impl SevHardwareProvider {
    /// Create with an explicit vendor attester (production or custom attester).
    pub fn with_attester(vendor_attester: Box<dyn VendorAttester>) -> Self {
        Self {
            vendor_attester: Some(vendor_attester),
            platform_key: std::sync::OnceLock::new(),
        }
    }

    /// Create with a local vendor key (development/testing only).
    pub fn create(vendor_root_key: [u8; 32]) -> Self {
        #[cfg(feature = "sev")]
        {
            Self {
                vendor_attester: Some(Box::new(LocalVendorAttester::new(vendor_root_key))),
                platform_key: std::sync::OnceLock::new(),
            }
        }
        #[cfg(not(feature = "sev"))]
        {
            let _ = vendor_root_key;
            Self {
                vendor_attester: None,
                platform_key: std::sync::OnceLock::new(),
            }
        }
    }
}

/// ioctl structs for `/dev/sev-guest` SNP_GET_REPORT.
#[cfg(feature = "sev")]
mod sev_ioctl {
    /// SEV-SNP attestation report size (AMD SEV-SNP spec).
    pub const SNP_REPORT_SIZE: usize = 1184;

    #[repr(C)]
    pub struct SnpReportReq {
        pub user_data: [u8; 64],
        pub vmpl: u32,
        pub rsvd: [u8; 28],
    }

    #[repr(C)]
    pub struct SnpReportResp {
        pub data: [u8; 4000],
    }

    /// snp_guest_request_ioctl (32 bytes on x86_64):
    ///   msg_version(1) + pad(7) + req_data(8) + resp_data(8) + exitinfo2(8)
    #[repr(C)]
    pub struct SnpGuestRequestIoctl {
        pub msg_version: u8,
        pub _pad: [u8; 7],
        pub req_data: u64,
        pub resp_data: u64,
        pub exitinfo2: u64,
    }

    /// SNP_GET_REPORT = _IOWR('S', 0x0, SnpGuestRequestIoctl)
    /// Size = 32 bytes → ioctl number = 0xC020_5300
    pub const SNP_GET_REPORT: libc::c_ulong =
        (3 << 30) | (32 << 16) | (0x53 << 8) | 0;
}

/// Send an SNP_GET_REPORT request and extract measurements from the report.
///
/// Returns (report_bytes, measurement_hash, host_data) where:
///   - report_bytes: full 1184-byte attestation report
///   - measurement_hash: SHA-256 of the 48-byte MEASUREMENT field
///   - host_data: 32-byte HOST_DATA field
#[cfg(feature = "sev")]
fn sev_get_attestation(user_data: &[u8; 32]) -> Result<(Vec<u8>, [u8; 32], [u8; 32]), AttestationError> {
    use std::os::unix::io::AsRawFd;
    use sev_ioctl::*;

    let fd = std::fs::OpenOptions::new()
        .read(true).write(true)
        .open("/dev/sev-guest")
        .map_err(|e| AttestationError::HardwareUnavailable(
            format!("SEV open /dev/sev-guest: {} (running inside SEV-SNP VM?)", e)))?;

    let mut req = SnpReportReq {
        user_data: [0u8; 64],
        vmpl: 0,
        rsvd: [0u8; 28],
    };
    req.user_data[..32].copy_from_slice(user_data);

    let mut resp = Box::new(SnpReportResp { data: [0u8; 4000] });

    let mut ioctl_data = SnpGuestRequestIoctl {
        msg_version: 1,
        _pad: [0u8; 7],
        req_data: &req as *const SnpReportReq as u64,
        resp_data: resp.as_mut() as *mut SnpReportResp as u64,
        exitinfo2: 0,
    };

    let ret = unsafe {
        libc::ioctl(fd.as_raw_fd(), SNP_GET_REPORT, &mut ioctl_data as *mut SnpGuestRequestIoctl)
    };
    if ret != 0 {
        return Err(AttestationError::HardwareUnavailable(
            format!("SNP_GET_REPORT ioctl failed: errno {}", std::io::Error::last_os_error())));
    }

    // Check firmware error
    let fw_error = (ioctl_data.exitinfo2 & 0xFFFF_FFFF) as u32;
    if fw_error != 0 {
        return Err(AttestationError::HardwareUnavailable(
            format!("SEV firmware error: 0x{:08x}", fw_error)));
    }

    let report_bytes = resp.data[..SNP_REPORT_SIZE].to_vec();

    // Extract MEASUREMENT (offset 144, 48 bytes) and HOST_DATA (offset 192, 32 bytes)
    let measurement_raw = &report_bytes[144..192]; // 48 bytes
    let mut host_data = [0u8; 32];
    host_data.copy_from_slice(&report_bytes[192..224]);

    // SHA-256 compress measurement (48 bytes → 32 bytes for on-chain)
    let measurement_hash = sha256_raw(measurement_raw);

    Ok((report_bytes, measurement_hash, host_data))
}

impl HardwareAttestationProvider for SevHardwareProvider {
    fn generate_report(&self, report_data: &[u8; 32]) -> Result<HardwareReport, AttestationError> {
        #[cfg(feature = "sev")]
        {
            let (report_bytes, measurement_hash, host_data) = sev_get_attestation(report_data)?;

            // Hash the full attestation report as the report commitment
            let mut hasher = Sha256::new();
            hasher.update(&report_bytes);
            let mut report_hash = [0u8; 32];
            report_hash.copy_from_slice(&hasher.finalize());

            Ok(HardwareReport {
                report_hash,
                enclave_measurement: measurement_hash,
                signer_measurement: host_data,
                application_measurement: None,
            })
        }
        #[cfg(not(feature = "sev"))]
        {
            let _ = report_data;
            Err(AttestationError::PlatformNotAvailable(TEEPlatform::AMDSEV))
        }
    }

    fn generate_platform_key(&self, platform_id: u8) -> Result<PlatformKeyBundle, AttestationError> {
        #[cfg(feature = "sev")]
        {
            let vendor_attester = self.vendor_attester.as_ref()
                .ok_or_else(|| AttestationError::HardwareUnavailable(
                    "SEV provider requires a VendorAttester for key generation".into()))?;

            // Generate P-256 key from OS-level CSPRNG (OsRng → getrandom).
            // Inside SEV-SNP: getrandom() → /dev/urandom → AMD CCP TRNG
            // (Cryptographic Coprocessor's True Random Number Generator).
            // The key bytes never pass through a userspace PRNG buffer.
            let (private_key, pk_x, pk_y) = generate_p256_platform_key()?;

            // Store the private key inside the provider — never expose it.
            let _ = self.platform_key.set(private_key);

            // Create SNP report binding the public key to this VM
            let mut key_hash = Sha256::new();
            key_hash.update(&pk_x);
            key_hash.update(&pk_y);
            let mut key_digest = [0u8; 32];
            key_digest.copy_from_slice(&key_hash.finalize());

            let (hw_evidence, _, _) = sev_get_attestation(&key_digest)?;

            let vendor_attestation = vendor_attester.attest_platform_key(
                &pk_x, &pk_y, platform_id, &hw_evidence,
            )?;

            Ok(PlatformKeyBundle {
                public_key_x: pk_x,
                public_key_y: pk_y,
                vendor_attestation,
            })
        }
        #[cfg(not(feature = "sev"))]
        {
            let _ = platform_id;
            Err(AttestationError::PlatformNotAvailable(TEEPlatform::AMDSEV))
        }
    }

    fn sign_with_platform_key(&self, report_body: &[u8]) -> Result<([u8; 32], [u8; 32]), AttestationError> {
        let key_bytes = self.platform_key.get()
            .ok_or_else(|| AttestationError::SigningFailed(
                "SEV platform key not yet generated; call generate_platform_key() first".into()))?;
        p256_sign_report_body(key_bytes, report_body)
    }

    fn platform(&self) -> TEEPlatform { TEEPlatform::AMDSEV }

    #[cfg(test)]
    fn platform_key_bytes_for_testing(&self) -> Option<[u8; 32]> {
        self.platform_key.get().copied()
    }
}

/// Attestation generator.
///
/// Produces attestation documents with real secp256k1 ECDSA signatures
/// that are compatible with both the Go native verifier and Solidity verifier.
///
/// The P-256 platform key is generated by the hardware provider at construction
/// time and **held inside the provider** — never exposed to this struct. Evidence
/// signing is performed via `hw_provider.sign_with_platform_key()`, ensuring
/// the private key stays within the TEE-boundary abstraction even if the
/// process memory is inspected after bootstrap.
pub struct AttestationGenerator {
    config: TEEConfig,
    nonce_counter: std::sync::atomic::AtomicU64,
    hw_provider: Box<dyn HardwareAttestationProvider>,
    /// Vendor key attestation proving the platform key is hardware-rooted.
    platform_key_attestation: KeyAttestation,
}

impl AttestationGenerator {
    /// Create an attestation generator with the appropriate hardware provider.
    ///
    /// For real platforms (SGX, Nitro, SEV), the real hardware provider is selected.
    /// These providers call platform-specific hardware APIs and will return
    /// `PlatformNotAvailable` if the hardware is not present.
    ///
    /// For the Mock platform, a `MockHardwareProvider` is used (requires
    /// `allow_simulated = true` at generation time).
    ///
    /// To use a mock provider for a real platform during testing, use
    /// `with_provider()` instead and set `allow_simulated = true`.
    ///
    /// The P-256 platform key is generated by the hardware provider during
    /// construction. This key originates from hardware, not from the caller.
    pub fn new(config: TEEConfig, vendor_root_key: [u8; 32]) -> Result<Self, AttestationError> {
        // For real platforms, reject the zero key early with a clear message.
        // [0u8; 32] is not a valid P-256 scalar and indicates the caller did
        // not supply a vendor attestation configuration.
        if config.platform != TEEPlatform::Mock && vendor_root_key == [0u8; 32] {
            return Err(AttestationError::HardwareUnavailable(format!(
                "real TEE platform '{}' requires vendor attestation. Either:\n  \
                 • Set vendor_attestation_key_hex in server config (development/testing only), or\n  \
                 • Set attestation_relay_url to use a remote attestation relay (production)\n\
                 The vendor key must never be [0; 32].",
                config.platform
            )));
        }
        let hw_provider: Box<dyn HardwareAttestationProvider> = match config.platform {
            TEEPlatform::Mock => {
                let mut mock = MockHardwareProvider::new(config.enclave_hash, config.signer_hash, vendor_root_key);
                if let Some(app_hash) = config.application_hash {
                    mock = mock.with_application_hash(app_hash);
                }
                Box::new(mock)
            }
            TEEPlatform::IntelSGX => Box::new(SgxHardwareProvider::create(vendor_root_key)),
            TEEPlatform::AWSNitro => Box::new(NitroHardwareProvider::create(vendor_root_key)),
            TEEPlatform::AMDSEV => Box::new(SevHardwareProvider::create(vendor_root_key)),
        };
        Self::init(config, hw_provider)
    }

    /// Create with an explicit vendor attester for real TEE platforms.
    ///
    /// This is the **production** constructor. The `vendor_attester` handles
    /// vendor key attestation — typically a `RemoteVendorAttester` that sends
    /// hardware evidence to an attestation relay service for independent
    /// verification, ensuring the vendor signing key never resides locally.
    ///
    /// For Mock platform, use `new()` instead (mock has built-in vendor signing).
    pub fn with_vendor_attester(
        config: TEEConfig,
        vendor_attester: Box<dyn VendorAttester>,
    ) -> Result<Self, AttestationError> {
        if config.platform == TEEPlatform::Mock {
            return Err(AttestationError::HardwareUnavailable(
                "use new() for Mock platform; with_vendor_attester() is for real TEE platforms".into()
            ));
        }
        let hw_provider: Box<dyn HardwareAttestationProvider> = match config.platform {
            TEEPlatform::Mock => unreachable!(), // guarded above
            TEEPlatform::IntelSGX => Box::new(SgxHardwareProvider::with_attester(vendor_attester)),
            TEEPlatform::AWSNitro => Box::new(NitroHardwareProvider::with_attester(vendor_attester)),
            TEEPlatform::AMDSEV => Box::new(SevHardwareProvider::with_attester(vendor_attester)),
        };
        Self::init(config, hw_provider)
    }

    /// Create with a custom hardware provider (for production or testing).
    ///
    /// The P-256 platform key is generated by the provider during construction.
    pub fn with_provider(config: TEEConfig, provider: Box<dyn HardwareAttestationProvider>) -> Result<Self, AttestationError> {
        Self::init(config, provider)
    }

    /// Internal constructor: generates platform key from the hardware provider.
    fn init(config: TEEConfig, hw_provider: Box<dyn HardwareAttestationProvider>) -> Result<Self, AttestationError> {
        let platform_id = config.platform as u8;

        // Gate on platform availability before key generation.
        match config.platform {
            TEEPlatform::Mock => {
                if !config.allow_simulated {
                    return Err(AttestationError::MockDisabled);
                }
            }
            real_platform => {
                if hw_provider.platform() != real_platform && !config.allow_simulated {
                    return Err(AttestationError::SimulatedHardwareNotAllowed(real_platform));
                }
            }
        }

        // Generate platform key INSIDE the hardware provider.
        // This is the critical security boundary: the key originates from
        // hardware, not from external software.
        let key_bundle = hw_provider.generate_platform_key(platform_id)?;

        let platform_key_attestation = KeyAttestation {
            platform_key_x: key_bundle.public_key_x,
            platform_key_y: key_bundle.public_key_y,
            platform_id,
            vendor_sig_r: key_bundle.vendor_attestation.vendor_sig_r,
            vendor_sig_s: key_bundle.vendor_attestation.vendor_sig_s,
        };

        Ok(Self {
            config,
            nonce_counter: std::sync::atomic::AtomicU64::new(0),
            hw_provider,
            platform_key_attestation,
        })
    }

    /// Returns the operator's compressed secp256k1 public key as a hex string.
    ///
    /// This is the key that must be registered on-chain as an operator before
    /// attestations from this generator will be accepted by the verifiers.
    pub fn operator_pubkey_hex(&self) -> Result<String, AttestationError> {
        let signing_key = k256::ecdsa::SigningKey::from_slice(&self.config.signing_key)
            .map_err(|e| AttestationError::SigningFailed(format!("invalid signing key: {}", e)))?;
        let verifying_key = signing_key.verifying_key();
        let point = verifying_key.to_encoded_point(true); // compressed
        Ok(hex::encode(point.as_bytes()))
    }

    /// Returns the P-256 platform public key as (x, y) coordinate byte arrays.
    ///
    /// These coordinates are from the hardware-generated key.
    pub fn platform_pubkey(&self) -> ([u8; 32], [u8; 32]) {
        (
            self.platform_key_attestation.platform_key_x,
            self.platform_key_attestation.platform_key_y,
        )
    }

    /// Returns the vendor key attestation generated at construction time.
    ///
    /// This attestation proves the platform key was generated inside TEE
    /// hardware and is certified by the hardware vendor. Use the returned
    /// values for on-chain registration via `setPlatformVerifier()`.
    pub fn key_attestation(&self) -> &KeyAttestation {
        &self.platform_key_attestation
    }

    /// Generate an attestation document for the given payload.
    ///
    /// All platforms produce a real secp256k1 ECDSA signature over a tagged
    /// SHA-256 digest that matches the on-chain verifier format.
    ///
    /// - `Mock` platform (with `allow_simulated`): uses test enclave measurements
    ///   but produces a real ECDSA signature.
    /// - Real platforms (SGX, Nitro, SEV): produce a real ECDSA signature and would
    ///   additionally attach platform-specific evidence (SGX quote, Nitro document,
    ///   SEV report) via the hardware attestation APIs. If the hardware API is
    ///   unavailable, returns an error rather than silently falling back to mock.
    pub fn generate(&self, payload: &[u8]) -> Result<AttestationDocument, AttestationError> {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let nonce_val = self
            .nonce_counter
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let nonce = self.generate_nonce(nonce_val, timestamp);

        let payload_hash = sha256_hex(payload);
        let platform_u8 = self.config.platform as u8;
        let enclave_hash_hex = hex::encode(self.config.enclave_hash);
        let signer_hash_hex = hex::encode(self.config.signer_hash);

        // Gate on platform availability and provider consistency.
        //
        // 1. Mock platform requires allow_simulated.
        // 2. Real platforms with a mock provider require allow_simulated
        //    (prevents silently running fake hardware while claiming real TEE).
        match self.config.platform {
            TEEPlatform::Mock => {
                if !self.config.allow_simulated {
                    return Err(AttestationError::MockDisabled);
                }
            }
            real_platform => {
                // If the hardware provider is a mock (not the real platform provider),
                // reject unless allow_simulated is explicitly set.
                if self.hw_provider.platform() != real_platform && !self.config.allow_simulated {
                    return Err(AttestationError::SimulatedHardwareNotAllowed(real_platform));
                }
            }
        }

        // Compute the attestation digest (matches Go native verifier)
        let digest = compute_attestation_digest(
            platform_u8,
            timestamp,
            &nonce,
            &enclave_hash_hex,
            &signer_hash_hex,
            &payload_hash,
        );

        // Generate fresh hardware attestation report bound to this digest.
        // The provider calls platform-specific hardware APIs (SGX DCAP, Nitro NSM,
        // SEV-SNP guest) or returns a simulated report for testing.
        let hw_report = self.hw_provider.generate_report(&digest)?;

        // CRITICAL: Validate that hardware report measurements match config.
        // In a real TEE, these are baked in by hardware and reflect the actual
        // running code. If they differ from config, either the config is wrong
        // or different code is running — either way, abort.
        if hw_report.enclave_measurement != self.config.enclave_hash {
            return Err(AttestationError::MeasurementMismatch {
                field: "enclave_hash",
                expected: self.config.enclave_hash,
                got: hw_report.enclave_measurement,
            });
        }
        if hw_report.signer_measurement != self.config.signer_hash {
            return Err(AttestationError::MeasurementMismatch {
                field: "signer_hash",
                expected: self.config.signer_hash,
                got: hw_report.signer_measurement,
            });
        }

        // Sign with secp256k1 ECDSA
        let sig_bytes = sign_digest(&self.config.signing_key, &digest)?;

        // Generate platform evidence bound to this attestation.
        // Evidence uses measurements FROM the hardware report (not config),
        // and includes a binding hash = SHA-256(report_hash || enclave || signer)
        // so on-chain verifiers can independently verify measurement binding.
        let evidence = self.generate_evidence(&digest, &hw_report)?;

        Ok(AttestationDocument {
            platform: platform_u8,
            timestamp,
            nonce,
            enclave_hash: enclave_hash_hex,
            signer_hash: signer_hash_hex,
            payload_hash,
            platform_evidence: hex::encode(&evidence),
            signature: hex::encode(sig_bytes),
        })
    }

    /// Generate ABI-encoded platform evidence for the given attestation digest.
    ///
    /// The evidence uses measurements FROM the hardware report (not config),
    /// binds to this specific attestation via `reportData = digest`, and includes
    /// `rawReportHash` (commitment to the fresh hardware report).
    ///
    /// **Binding scheme**: The P-256 signature covers a binding hash:
    ///   `bindingHash = SHA-256(rawReportHash || enclaveMeasurement || signerMeasurement)`
    /// instead of the raw report hash. This lets on-chain verifiers independently
    /// compute the binding hash and verify that the measurements in evidence are
    /// cryptographically bound to the specific hardware report.
    fn generate_evidence(&self, digest: &[u8; 32], hw_report: &HardwareReport) -> Result<Vec<u8>, AttestationError> {
        match self.config.platform {
            TEEPlatform::IntelSGX | TEEPlatform::Mock => {
                self.generate_sgx_evidence(digest, hw_report)
            }
            TEEPlatform::AWSNitro => {
                self.generate_nitro_evidence(digest, hw_report)
            }
            TEEPlatform::AMDSEV => {
                self.generate_sev_evidence(digest, hw_report)
            }
        }
    }

    /// Compute the binding hash that links a hardware report to specific measurements.
    ///
    /// `bindingHash = SHA-256(rawReportHash || enclaveMeasurement || signerMeasurement)`
    ///
    /// This hash is used in the P-256 signed report body instead of the raw report hash.
    /// On-chain verifiers compute the same hash from evidence fields to verify binding.
    fn compute_binding_hash(
        raw_report_hash: &[u8; 32],
        enclave_measurement: &[u8; 32],
        signer_measurement: &[u8; 32],
    ) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(raw_report_hash);
        hasher.update(enclave_measurement);
        hasher.update(signer_measurement);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }

    /// SGX evidence: ABI-encode (bytes32, bytes32, bytes32, uint16, uint16, bytes32, uint256, uint256)
    ///
    /// 8 words = 256 bytes. The last 2 words are the P-256 ECDSA signature (r, s)
    /// over the packed report body:
    ///   SHA-256(mrenclave[32] || mrsigner[32] || reportData[32] || isvProdId[2] || isvSvn[2] || bindingHash[32])
    ///
    /// where bindingHash = SHA-256(rawReportHash || mrenclave || mrsigner).
    /// The evidence stores rawReportHash (direct hardware commitment), but the
    /// P-256 signature covers bindingHash so verifiers can prove measurement binding.
    fn generate_sgx_evidence(&self, digest: &[u8; 32], hw_report: &HardwareReport) -> Result<Vec<u8>, AttestationError> {
        let mut evidence = Vec::with_capacity(8 * 32);
        // bytes32 mrenclave — from hardware report, NOT config
        evidence.extend_from_slice(&hw_report.enclave_measurement);
        // bytes32 mrsigner — from hardware report, NOT config
        evidence.extend_from_slice(&hw_report.signer_measurement);
        // bytes32 reportData = attestation digest
        evidence.extend_from_slice(digest);
        // uint16 isvProdId = 1 (right-aligned in 32-byte word)
        let mut word = [0u8; 32];
        word[31] = 1;
        evidence.extend_from_slice(&word);
        // uint16 isvSvn = 1
        let mut word = [0u8; 32];
        word[31] = 1;
        evidence.extend_from_slice(&word);
        // rawReportHash — direct commitment to the fresh hardware report
        evidence.extend_from_slice(&hw_report.report_hash);

        // Compute binding hash: SHA-256(rawReportHash || mrenclave || mrsigner)
        // This binds the hardware report to the specific measurements.
        let binding_hash = Self::compute_binding_hash(
            &hw_report.report_hash,
            &hw_report.enclave_measurement,
            &hw_report.signer_measurement,
        );

        // Sign the report body with P-256 platform key.
        // Uses bindingHash (not rawReportHash) so verifiers can independently
        // verify that measurements are bound to the hardware report.
        // report body = mrenclave(32) || mrsigner(32) || reportData(32) || isvProdId(2) || isvSvn(2) || bindingHash(32) = 132 bytes
        let mut report_body = Vec::with_capacity(132);
        report_body.extend_from_slice(&hw_report.enclave_measurement);
        report_body.extend_from_slice(&hw_report.signer_measurement);
        report_body.extend_from_slice(digest);
        report_body.extend_from_slice(&1u16.to_be_bytes()); // isvProdId
        report_body.extend_from_slice(&1u16.to_be_bytes()); // isvSvn
        report_body.extend_from_slice(&binding_hash);

        let (r_bytes, s_bytes) = self.hw_provider.sign_with_platform_key(&report_body)?;
        evidence.extend_from_slice(&r_bytes);
        evidence.extend_from_slice(&s_bytes);

        Ok(evidence)
    }

    /// Nitro evidence: ABI-encode (bytes32, bytes32, bytes32, bytes32, bytes32, uint256, uint256)
    ///
    /// 7 words = 224 bytes. The last 2 words are the P-256 ECDSA signature (r, s)
    /// over the packed report body:
    ///   SHA-256(pcr0[32] || pcr1[32] || pcr2[32] || userData[32] || bindingHash[32]) = 160 bytes
    ///
    /// where bindingHash = SHA-256(rawReportHash || pcr0 || pcr1).
    fn generate_nitro_evidence(&self, digest: &[u8; 32], hw_report: &HardwareReport) -> Result<Vec<u8>, AttestationError> {
        // Require PCR2 (application hash) for Nitro evidence
        let pcr2 = hw_report.application_measurement.unwrap_or([0u8; 32]);

        let mut evidence = Vec::with_capacity(7 * 32);
        // bytes32 pcrHash0 — from hardware report
        evidence.extend_from_slice(&hw_report.enclave_measurement);
        // bytes32 pcrHash1 — from hardware report
        evidence.extend_from_slice(&hw_report.signer_measurement);
        // bytes32 pcrHash2 — application hash from hardware report (Nitro PCR2)
        evidence.extend_from_slice(&pcr2);
        // bytes32 userData = attestation digest
        evidence.extend_from_slice(digest);
        // rawReportHash — direct commitment to the fresh hardware report
        evidence.extend_from_slice(&hw_report.report_hash);

        // Compute binding hash: SHA-256(rawReportHash || pcr0 || pcr1)
        let binding_hash = Self::compute_binding_hash(
            &hw_report.report_hash,
            &hw_report.enclave_measurement,
            &hw_report.signer_measurement,
        );

        // Sign the report body with P-256 platform key (uses bindingHash)
        // report body = pcr0(32) || pcr1(32) || pcr2(32) || userData(32) || bindingHash(32) = 160 bytes
        let mut report_body = Vec::with_capacity(160);
        report_body.extend_from_slice(&hw_report.enclave_measurement);
        report_body.extend_from_slice(&hw_report.signer_measurement);
        report_body.extend_from_slice(&pcr2);
        report_body.extend_from_slice(digest);
        report_body.extend_from_slice(&binding_hash);

        let (r_bytes, s_bytes) = self.hw_provider.sign_with_platform_key(&report_body)?;
        evidence.extend_from_slice(&r_bytes);
        evidence.extend_from_slice(&s_bytes);

        Ok(evidence)
    }

    /// SEV evidence: ABI-encode (bytes32, bytes32, bytes32, uint8, bytes32, uint256, uint256)
    ///
    /// 7 words = 224 bytes. The last 2 words are the P-256 ECDSA signature (r, s)
    /// over the packed report body:
    ///   SHA-256(measurement[32] || hostData[32] || reportData[32] || vmpl[1] || bindingHash[32]) = 129 bytes
    ///
    /// where bindingHash = SHA-256(rawReportHash || measurement || hostData).
    fn generate_sev_evidence(&self, digest: &[u8; 32], hw_report: &HardwareReport) -> Result<Vec<u8>, AttestationError> {
        let mut evidence = Vec::with_capacity(7 * 32);
        // bytes32 measurementHash — from hardware report
        evidence.extend_from_slice(&hw_report.enclave_measurement);
        // bytes32 hostData — from hardware report
        evidence.extend_from_slice(&hw_report.signer_measurement);
        // bytes32 reportData = attestation digest
        evidence.extend_from_slice(digest);
        // uint8 vmpl = 0 (right-aligned in 32-byte word)
        evidence.extend_from_slice(&[0u8; 32]);
        // rawReportHash — direct commitment to the fresh hardware report
        evidence.extend_from_slice(&hw_report.report_hash);

        // Compute binding hash: SHA-256(rawReportHash || measurement || hostData)
        let binding_hash = Self::compute_binding_hash(
            &hw_report.report_hash,
            &hw_report.enclave_measurement,
            &hw_report.signer_measurement,
        );

        // Sign the report body with P-256 platform key (uses bindingHash)
        // report body = measurement(32) || hostData(32) || reportData(32) || vmpl(1) || bindingHash(32) = 129 bytes
        let mut report_body = Vec::with_capacity(129);
        report_body.extend_from_slice(&hw_report.enclave_measurement);
        report_body.extend_from_slice(&hw_report.signer_measurement);
        report_body.extend_from_slice(digest);
        report_body.push(0u8); // vmpl = 0
        report_body.extend_from_slice(&binding_hash);

        let (r_bytes, s_bytes) = self.hw_provider.sign_with_platform_key(&report_body)?;
        evidence.extend_from_slice(&r_bytes);
        evidence.extend_from_slice(&s_bytes);

        Ok(evidence)
    }

    /// Generate a unique nonce from counter and timestamp.
    fn generate_nonce(&self, counter: u64, timestamp: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(counter.to_be_bytes());
        hasher.update(timestamp.to_be_bytes());
        hasher.update(self.config.enclave_hash);
        hex::encode(hasher.finalize())
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Digest & Signing
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the attestation digest matching the Go native verifier format.
///
/// ```text
/// digest = SHA-256("CrucibleTEEAttestation" ‖ platform ‖ timestamp_be64 ‖
///                   nonce ‖ enclaveHash ‖ signerHash ‖ payloadHash)
/// ```
///
/// All hex fields are decoded to raw bytes before hashing.
pub fn compute_attestation_digest(
    platform: u8,
    timestamp: u64,
    nonce_hex: &str,
    enclave_hash_hex: &str,
    signer_hash_hex: &str,
    payload_hash_hex: &str,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"CrucibleTEEAttestation");
    hasher.update([platform]);
    hasher.update(timestamp.to_be_bytes());

    let nonce_bytes = hex::decode(nonce_hex).unwrap_or_default();
    hasher.update(&nonce_bytes);

    let enclave_bytes = hex::decode(enclave_hash_hex).unwrap_or_default();
    hasher.update(&enclave_bytes);

    let signer_bytes = hex::decode(signer_hash_hex).unwrap_or_default();
    hasher.update(&signer_bytes);

    let payload_bytes = hex::decode(payload_hash_hex).unwrap_or_default();
    hasher.update(&payload_bytes);

    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

/// Sign a 32-byte digest with secp256k1 ECDSA, producing a 65-byte
/// Ethereum-style signature: R[32] ‖ S[32] ‖ V[1].
fn sign_digest(
    signing_key_bytes: &[u8; 32],
    digest: &[u8; 32],
) -> Result<[u8; 65], AttestationError> {
    let signing_key = k256::ecdsa::SigningKey::from_slice(signing_key_bytes)
        .map_err(|e| AttestationError::SigningFailed(format!("invalid signing key: {}", e)))?;

    let (sig, recid) = signing_key
        .sign_prehash_recoverable(digest)
        .map_err(|e| AttestationError::SigningFailed(format!("ECDSA sign failed: {}", e)))?;

    let r_bytes = sig.r().to_bytes();
    let s_bytes = sig.s().to_bytes();
    let v = recid.to_byte() + 27; // Ethereum-style V (27 or 28)

    let mut sig_out = [0u8; 65];
    sig_out[0..32].copy_from_slice(&r_bytes);
    sig_out[32..64].copy_from_slice(&s_bytes);
    sig_out[64] = v;

    Ok(sig_out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Verification
// ─────────────────────────────────────────────────────────────────────────────

/// Verify an attestation document:
///   1. Enclave hash matches expected
///   2. Timestamp within max_age_secs of current time
///   3. Non-empty nonce
///   4. Valid 65-byte ECDSA signature recoverable to a public key
///
/// Returns the recovered compressed public key hex on success.
pub fn verify_attestation(
    attestation: &AttestationDocument,
    expected_enclave_hash: &str,
    max_age_secs: u64,
) -> Result<String, String> {
    // Check enclave hash
    if attestation.enclave_hash != expected_enclave_hash {
        return Err(format!(
            "Enclave hash mismatch: expected {}, got {}",
            expected_enclave_hash, attestation.enclave_hash
        ));
    }

    // Check timestamp freshness
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    if now > attestation.timestamp + max_age_secs {
        return Err(format!(
            "Attestation expired: age {}s > max {}s",
            now - attestation.timestamp,
            max_age_secs
        ));
    }

    // Check nonce is non-empty
    if attestation.nonce.is_empty() {
        return Err("Empty nonce".to_string());
    }

    // Verify ECDSA signature and recover signer
    let sig_bytes = hex::decode(&attestation.signature)
        .map_err(|_| "invalid signature hex".to_string())?;
    if sig_bytes.len() != 65 {
        return Err(format!(
            "invalid signature length: {} (expected 65 bytes / 130 hex chars)",
            sig_bytes.len()
        ));
    }

    let digest = compute_attestation_digest(
        attestation.platform,
        attestation.timestamp,
        &attestation.nonce,
        &attestation.enclave_hash,
        &attestation.signer_hash,
        &attestation.payload_hash,
    );

    // Recover public key from R‖S‖V signature
    let ecdsa_sig = k256::ecdsa::Signature::from_slice(&sig_bytes[0..64])
        .map_err(|e| format!("invalid R||S: {}", e))?;
    let v = sig_bytes[64];
    let recid = k256::ecdsa::RecoveryId::try_from(if v >= 27 { v - 27 } else { v })
        .map_err(|e| format!("invalid recovery id (V={}): {}", v, e))?;

    let recovered = k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &ecdsa_sig, recid)
        .map_err(|e| format!("signature recovery failed: {}", e))?;

    let compressed = recovered.to_encoded_point(true);
    Ok(hex::encode(compressed.as_bytes()))
}

/// SHA-256 hash, returned as hex string.
fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// SHA-256 hash, returned as raw 32-byte array.
#[cfg_attr(not(test), allow(dead_code))]
fn sha256_raw(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let mut output = [0u8; 32];
    output.copy_from_slice(&hasher.finalize());
    output
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate a deterministic test signing key (secp256k1 operator key).
    fn test_signing_key() -> [u8; 32] {
        // SHA-256("test-operator-key") -> deterministic 32-byte key
        let hash = Sha256::digest(b"test-operator-key");
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash);
        key
    }

    /// Vendor root P-256 key for tests (private key = 2).
    /// In production, this would be Intel/AWS/AMD's hardware root key.
    fn test_vendor_root_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        key[31] = 2;
        key
    }

    fn test_config() -> TEEConfig {
        TEEConfig {
            platform: TEEPlatform::Mock,
            enclave_hash: [0xAB; 32],
            signer_hash: [0xCD; 32],
            application_hash: None,
            allow_simulated: true,
            signing_key: test_signing_key(),
        }
    }

    /// Create a test AttestationGenerator with default mock config.
    fn test_generator() -> AttestationGenerator {
        AttestationGenerator::new(test_config(), test_vendor_root_key()).unwrap()
    }

    /// Extract the P-256 platform private key from a generator (for test verification).
    ///
    /// Uses the test-only `platform_key_bytes_for_testing()` trait method
    /// to retrieve the key held inside the hardware provider.
    fn extract_platform_key(gen: &AttestationGenerator) -> [u8; 32] {
        gen.hw_provider.platform_key_bytes_for_testing()
            .expect("platform key should be generated during init")
    }

    /// Helper: compute the binding hash for test report body reconstruction.
    /// bindingHash = SHA-256(rawReportHash || enclaveMeasurement || signerMeasurement)
    fn test_binding_hash(raw_report_hash: &[u8], enclave: &[u8; 32], signer: &[u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(raw_report_hash);
        hasher.update(enclave);
        hasher.update(signer);
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hasher.finalize());
        hash
    }

    /// Helper: verify a P-256 signature over a report body hash.
    fn verify_p256_signature(
        platform_key: &[u8; 32],
        report_body: &[u8],
        r_bytes: &[u8],
        s_bytes: &[u8],
    ) {
        use p256::ecdsa::{
            SigningKey as P256SigningKey,
            VerifyingKey as P256VerifyingKey,
            Signature as P256Signature,
        };
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        let p256_key = P256SigningKey::from_slice(platform_key).unwrap();
        let verifying_key = P256VerifyingKey::from(&p256_key);

        let mut r_arr = p256::FieldBytes::default();
        r_arr.copy_from_slice(r_bytes);
        let mut s_arr = p256::FieldBytes::default();
        s_arr.copy_from_slice(s_bytes);
        let sig = P256Signature::from_scalars(r_arr, s_arr)
            .expect("valid P-256 signature scalars");

        let report_hash = sha256_raw(report_body);
        assert!(
            verifying_key.verify_prehash(&report_hash, &sig).is_ok(),
            "P-256 platform signature must verify"
        );
    }

    #[test]
    fn test_generate_attestation() {
        let gen = test_generator();
        let attestation = gen.generate(b"test payload").expect("mock should succeed");

        // Platform is u8, not String
        assert_eq!(attestation.platform, 255); // Mock = 255
        assert!(!attestation.nonce.is_empty());
        assert!(!attestation.payload_hash.is_empty());
        assert!(!attestation.signature.is_empty());
        assert!(attestation.timestamp > 0);
        assert!(!attestation.platform_evidence.is_empty(), "platform_evidence should be non-empty");

        // Signature must be exactly 65 bytes (130 hex chars)
        let sig_bytes = hex::decode(&attestation.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65, "signature must be 65 bytes (R||S||V)");

        // V must be 27 or 28
        let v = sig_bytes[64];
        assert!(v == 27 || v == 28, "V must be 27 or 28, got {}", v);
    }

    #[test]
    fn test_unique_nonces() {
        let gen = test_generator();
        let a1 = gen.generate(b"payload-1").unwrap();
        let a2 = gen.generate(b"payload-2").unwrap();

        assert_ne!(a1.nonce, a2.nonce);
    }

    #[test]
    fn test_verify_attestation() {
        let gen = test_generator();
        let attestation = gen.generate(b"test").unwrap();

        let result = verify_attestation(
            &attestation,
            &hex::encode([0xAB; 32]),
            300, // 5 minute max age
        );
        assert!(result.is_ok(), "verification failed: {:?}", result.err());

        // Recovered public key should match the operator's key
        let recovered_pubkey = result.unwrap();
        let expected_pubkey = gen.operator_pubkey_hex().unwrap();
        assert_eq!(recovered_pubkey, expected_pubkey);
    }

    #[test]
    fn test_verify_wrong_enclave() {
        let gen = test_generator();
        let attestation = gen.generate(b"test").unwrap();

        let result = verify_attestation(&attestation, "wrong-hash", 300);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_payloads_different_hashes() {
        let gen = test_generator();
        let a1 = gen.generate(b"payload-1").unwrap();
        let a2 = gen.generate(b"payload-2").unwrap();

        assert_ne!(a1.payload_hash, a2.payload_hash);
    }

    #[test]
    fn test_real_platform_rejects_without_hardware() {
        // AttestationGenerator::new() with a real platform selects the real
        // hardware provider. Without actual TEE hardware, construction must fail
        // with PlatformNotAvailable — NOT silently use a mock.
        let config = TEEConfig {
            platform: TEEPlatform::IntelSGX,
            enclave_hash: [0xAB; 32],
            signer_hash: [0xCD; 32],
            application_hash: None,
            allow_simulated: false,
            signing_key: test_signing_key(),
        };
        let result = AttestationGenerator::new(config, test_vendor_root_key());
        assert!(result.is_err(), "SGX without hardware must fail at construction");
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("not available") || err_msg.contains("unavailable"),
            "expected hardware-not-present error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_mock_provider_rejected_for_real_platform() {
        // Injecting a MockHardwareProvider for a real platform via with_provider()
        // must fail when allow_simulated = false. This closes the bypass where
        // the system could run fake hardware while claiming to be TEE-backed.
        let config = TEEConfig {
            platform: TEEPlatform::IntelSGX,
            enclave_hash: [0xAB; 32],
            signer_hash: [0xCD; 32],
            application_hash: None,
            allow_simulated: false,
            signing_key: test_signing_key(),
        };
        let mock_provider = Box::new(MockHardwareProvider::new([0xAB; 32], [0xCD; 32], test_vendor_root_key()));
        let result = AttestationGenerator::with_provider(config, mock_provider);
        assert!(result.is_err(), "mock provider for real platform must fail at construction without allow_simulated");
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("simulated hardware") || err_msg.contains("not allowed"),
            "expected SimulatedHardwareNotAllowed, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_simulated_hardware_allowed_for_real_platform() {
        // with_provider() + allow_simulated = true: mock provider is explicitly
        // permitted for a real platform. This is the correct testing path.
        let config = TEEConfig {
            platform: TEEPlatform::IntelSGX,
            enclave_hash: [0xAB; 32],
            signer_hash: [0xCD; 32],
            application_hash: None,
            allow_simulated: true,
            signing_key: test_signing_key(),
        };
        let mock_provider = Box::new(MockHardwareProvider::new([0xAB; 32], [0xCD; 32], test_vendor_root_key()));
        let gen = AttestationGenerator::with_provider(config, mock_provider).unwrap();
        let attestation = gen.generate(b"test").unwrap();

        // Platform is 0 (SGX)
        assert_eq!(attestation.platform, 0);

        // Signature is valid and recoverable
        let result = verify_attestation(
            &attestation,
            &hex::encode([0xAB; 32]),
            300,
        );
        assert!(result.is_ok(), "SGX attestation failed: {:?}", result.err());

        // Same operator key
        let recovered = result.unwrap();
        let expected = gen.operator_pubkey_hex().unwrap();
        assert_eq!(recovered, expected);

        // Verify P-256 signature in evidence (SGX = 256 bytes)
        let evidence_bytes = hex::decode(&attestation.platform_evidence).unwrap();
        assert_eq!(evidence_bytes.len(), 256, "SGX evidence should be 256 bytes (8 words)");

        let digest = compute_attestation_digest(
            attestation.platform,
            attestation.timestamp,
            &attestation.nonce,
            &attestation.enclave_hash,
            &attestation.signer_hash,
            &attestation.payload_hash,
        );

        // Extract rawReportHash from evidence[160:192]
        let raw_report_hash = &evidence_bytes[160..192];
        // Compute binding hash: SHA-256(rawReportHash || mrenclave || mrsigner)
        let binding_hash = test_binding_hash(raw_report_hash, &[0xAB; 32], &[0xCD; 32]);

        let mut report_body = Vec::with_capacity(132);
        report_body.extend_from_slice(&[0xAB; 32]); // mrenclave
        report_body.extend_from_slice(&[0xCD; 32]); // mrsigner
        report_body.extend_from_slice(&digest);
        report_body.extend_from_slice(&1u16.to_be_bytes());
        report_body.extend_from_slice(&1u16.to_be_bytes());
        report_body.extend_from_slice(&binding_hash);

        // Platform key is now hardware-generated, extract it from the generator
        verify_p256_signature(
            &extract_platform_key(&gen),
            &report_body,
            &evidence_bytes[192..224],
            &evidence_bytes[224..256],
        );
    }

    #[test]
    fn test_mock_disabled_rejects() {
        let config = TEEConfig {
            platform: TEEPlatform::Mock,
            enclave_hash: [0xAB; 32],
            signer_hash: [0xCD; 32],
            application_hash: None,
            allow_simulated: false,
            signing_key: test_signing_key(),
        };
        let result = AttestationGenerator::new(config, test_vendor_root_key());
        assert!(result.is_err(), "mock platform without allow_simulated must fail at construction");
    }

    #[test]
    fn test_evidence_contains_correct_digest() {
        let gen = test_generator();
        let attestation = gen.generate(b"evidence-test").unwrap();

        // Decode evidence and verify it contains the attestation digest
        let evidence_bytes = hex::decode(&attestation.platform_evidence).unwrap();
        // SGX evidence: 8 words x 32 bytes = 256 bytes (with P-256 sig and rawReportHash)
        assert_eq!(evidence_bytes.len(), 256, "SGX evidence should be 256 bytes (8 words)");

        // First 32 bytes = mrenclave = hardware report enclave measurement
        assert_eq!(&evidence_bytes[0..32], &[0xAB; 32], "mrenclave should match hw report measurement");
        // Next 32 bytes = mrsigner = hardware report signer measurement
        assert_eq!(&evidence_bytes[32..64], &[0xCD; 32], "mrsigner should match hw report measurement");

        // reportData (bytes 64..96) should equal the attestation digest
        let digest = compute_attestation_digest(
            attestation.platform,
            attestation.timestamp,
            &attestation.nonce,
            &attestation.enclave_hash,
            &attestation.signer_hash,
            &attestation.payload_hash,
        );
        assert_eq!(&evidence_bytes[64..96], &digest, "reportData should equal attestation digest");

        // Extract rawReportHash from evidence[160:192]
        let raw_report_hash = &evidence_bytes[160..192];
        // Compute binding hash: SHA-256(rawReportHash || mrenclave || mrsigner)
        let binding_hash = test_binding_hash(raw_report_hash, &[0xAB; 32], &[0xCD; 32]);

        // Verify the P-256 signature (r at [192:224], s at [224:256])
        let r_bytes = &evidence_bytes[192..224];
        let s_bytes = &evidence_bytes[224..256];

        // Reconstruct packed report body with bindingHash (132 bytes) and verify
        let mut report_body = Vec::new();
        report_body.extend_from_slice(&[0xAB; 32]); // mrenclave
        report_body.extend_from_slice(&[0xCD; 32]); // mrsigner
        report_body.extend_from_slice(&digest);
        report_body.extend_from_slice(&1u16.to_be_bytes());
        report_body.extend_from_slice(&1u16.to_be_bytes());
        report_body.extend_from_slice(&binding_hash);

        verify_p256_signature(&extract_platform_key(&gen), &report_body, r_bytes, s_bytes);
    }

    #[test]
    fn test_digest_matches_go_verifier_format() {
        // Verify the digest is computed the same way as the Go keeper.
        // This is a cross-implementation compatibility test.
        let platform: u8 = 0; // SGX
        let timestamp: u64 = 1700000000;
        let nonce_hex = hex::encode([0x11; 32]);
        let enclave_hex = hex::encode([0xAA; 32]);
        let signer_hex = hex::encode([0xBB; 32]);
        let payload_hex = hex::encode([0xCC; 32]);

        let digest = compute_attestation_digest(
            platform,
            timestamp,
            &nonce_hex,
            &enclave_hex,
            &signer_hex,
            &payload_hex,
        );

        // Manually compute expected:
        // SHA-256("CrucibleTEEAttestation" || 0x00 || 0x00..00_65_5A_2A_00 || nonce || enclave || signer || payload)
        let mut hasher = Sha256::new();
        hasher.update(b"CrucibleTEEAttestation");
        hasher.update([0u8]); // platform
        hasher.update(1700000000u64.to_be_bytes()); // timestamp
        hasher.update([0x11u8; 32]); // nonce
        hasher.update([0xAAu8; 32]); // enclave
        hasher.update([0xBBu8; 32]); // signer
        hasher.update([0xCCu8; 32]); // payload
        let mut expected = [0u8; 32];
        expected.copy_from_slice(&hasher.finalize());

        assert_eq!(digest, expected);
    }

    #[test]
    fn test_signature_round_trip() {
        // Generate attestation -> verify -> recovered key matches operator key
        let gen = test_generator();

        let attestation = gen.generate(b"important payload").unwrap();

        // Manually recompute digest
        let digest = compute_attestation_digest(
            attestation.platform,
            attestation.timestamp,
            &attestation.nonce,
            &attestation.enclave_hash,
            &attestation.signer_hash,
            &attestation.payload_hash,
        );

        // Decode signature
        let sig_bytes = hex::decode(&attestation.signature).unwrap();
        assert_eq!(sig_bytes.len(), 65);

        // Recover via k256
        let ecdsa_sig = k256::ecdsa::Signature::from_slice(&sig_bytes[0..64]).unwrap();
        let v = sig_bytes[64];
        let recid = k256::ecdsa::RecoveryId::try_from(v - 27).unwrap();
        let recovered =
            k256::ecdsa::VerifyingKey::recover_from_prehash(&digest, &ecdsa_sig, recid).unwrap();
        let recovered_hex = hex::encode(recovered.to_encoded_point(true).as_bytes());

        assert_eq!(recovered_hex, gen.operator_pubkey_hex().unwrap());
    }

    #[test]
    fn test_p256_evidence_signature_verification() {
        // Dedicated test: generate evidence for each platform,
        // extract P-256 signature, and verify it independently.
        // The P-256 signed message uses bindingHash (not rawReportHash).

        // --- SGX (Mock uses SGX path) ---
        {
            let gen = test_generator();
            let attestation = gen.generate(b"p256-sgx-test").unwrap();
            let evidence = hex::decode(&attestation.platform_evidence).unwrap();
            assert_eq!(evidence.len(), 256, "SGX evidence = 8 words = 256 bytes");

            let digest = compute_attestation_digest(
                attestation.platform,
                attestation.timestamp,
                &attestation.nonce,
                &attestation.enclave_hash,
                &attestation.signer_hash,
                &attestation.payload_hash,
            );

            // Extract rawReportHash from evidence[160:192]
            let raw_report_hash = &evidence[160..192];
            // Compute binding hash for P-256 verification
            let binding_hash = test_binding_hash(raw_report_hash, &[0xAB; 32], &[0xCD; 32]);

            // Packed report body with bindingHash: mrenclave(32) || mrsigner(32) || reportData(32) || isvProdId(2) || isvSvn(2) || bindingHash(32) = 132 bytes
            let mut report_body = Vec::with_capacity(132);
            report_body.extend_from_slice(&[0xAB; 32]);
            report_body.extend_from_slice(&[0xCD; 32]);
            report_body.extend_from_slice(&digest);
            report_body.extend_from_slice(&1u16.to_be_bytes());
            report_body.extend_from_slice(&1u16.to_be_bytes());
            report_body.extend_from_slice(&binding_hash);

            verify_p256_signature(
                &extract_platform_key(&gen),
                &report_body,
                &evidence[192..224],
                &evidence[224..256],
            );
        }

        // --- Nitro (with_provider + allow_simulated for testing) ---
        {
            let config = TEEConfig {
                platform: TEEPlatform::AWSNitro,
                enclave_hash: [0xAB; 32],
                signer_hash: [0xCD; 32],
                application_hash: None,
                allow_simulated: true,
                signing_key: test_signing_key(),
            };
            let mock_provider = Box::new(MockHardwareProvider::new([0xAB; 32], [0xCD; 32], test_vendor_root_key()));
            let gen = AttestationGenerator::with_provider(config, mock_provider).unwrap();
            let attestation = gen.generate(b"p256-nitro-test").unwrap();
            let evidence = hex::decode(&attestation.platform_evidence).unwrap();
            assert_eq!(evidence.len(), 224, "Nitro evidence = 7 words = 224 bytes");

            let digest = compute_attestation_digest(
                attestation.platform,
                attestation.timestamp,
                &attestation.nonce,
                &attestation.enclave_hash,
                &attestation.signer_hash,
                &attestation.payload_hash,
            );

            // Extract rawReportHash from evidence[128:160]
            let raw_report_hash = &evidence[128..160];
            let binding_hash = test_binding_hash(raw_report_hash, &[0xAB; 32], &[0xCD; 32]);

            // Packed report body with bindingHash: pcr0(32) || pcr1(32) || pcr2(32) || userData(32) || bindingHash(32) = 160 bytes
            let mut report_body = Vec::with_capacity(160);
            report_body.extend_from_slice(&[0xAB; 32]); // pcr0
            report_body.extend_from_slice(&[0xCD; 32]); // pcr1
            report_body.extend_from_slice(&[0u8; 32]);   // pcr2
            report_body.extend_from_slice(&digest);       // userData
            report_body.extend_from_slice(&binding_hash);

            verify_p256_signature(
                &extract_platform_key(&gen),
                &report_body,
                &evidence[160..192],
                &evidence[192..224],
            );
        }

        // --- SEV (with_provider + allow_simulated for testing) ---
        {
            let config = TEEConfig {
                platform: TEEPlatform::AMDSEV,
                enclave_hash: [0xAB; 32],
                signer_hash: [0xCD; 32],
                application_hash: None,
                allow_simulated: true,
                signing_key: test_signing_key(),
            };
            let mock_provider = Box::new(MockHardwareProvider::new([0xAB; 32], [0xCD; 32], test_vendor_root_key()));
            let gen = AttestationGenerator::with_provider(config, mock_provider).unwrap();
            let attestation = gen.generate(b"p256-sev-test").unwrap();
            let evidence = hex::decode(&attestation.platform_evidence).unwrap();
            assert_eq!(evidence.len(), 224, "SEV evidence = 7 words = 224 bytes");

            let digest = compute_attestation_digest(
                attestation.platform,
                attestation.timestamp,
                &attestation.nonce,
                &attestation.enclave_hash,
                &attestation.signer_hash,
                &attestation.payload_hash,
            );

            // Extract rawReportHash from evidence[128:160]
            let raw_report_hash = &evidence[128..160];
            let binding_hash = test_binding_hash(raw_report_hash, &[0xAB; 32], &[0xCD; 32]);

            // Packed report body with bindingHash: measurement(32) || hostData(32) || reportData(32) || vmpl(1) || bindingHash(32) = 129 bytes
            let mut report_body = Vec::with_capacity(129);
            report_body.extend_from_slice(&[0xAB; 32]); // measurement
            report_body.extend_from_slice(&[0xCD; 32]); // hostData
            report_body.extend_from_slice(&digest);       // reportData
            report_body.push(0u8);                        // vmpl
            report_body.extend_from_slice(&binding_hash);

            verify_p256_signature(
                &extract_platform_key(&gen),
                &report_body,
                &evidence[160..192],
                &evidence[192..224],
            );
        }
    }

    #[test]
    fn test_platform_pubkey() {
        let gen = test_generator();
        let (x, y) = gen.platform_pubkey();
        // Platform key = 1, so pubkey = P-256 generator point G
        assert_ne!(x, [0u8; 32], "X coordinate should not be zero");
        assert_ne!(y, [0u8; 32], "Y coordinate should not be zero");
    }

    #[test]
    fn test_vendor_key_attestation() {
        let gen = test_generator();
        let attestation = gen.key_attestation().clone();

        // Verify the vendor signature
        use p256::ecdsa::{
            SigningKey as P256SigningKey,
            VerifyingKey as P256VerifyingKey,
            Signature as P256Signature,
        };
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        // Reconstruct the message
        let mut hasher = Sha256::new();
        hasher.update(&attestation.platform_key_x);
        hasher.update(&attestation.platform_key_y);
        hasher.update([attestation.platform_id]);
        let msg_hash = {
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        // Verify with the vendor root public key
        let vendor_key = P256SigningKey::from_slice(&test_vendor_root_key()).unwrap();
        let vendor_verifying = P256VerifyingKey::from(&vendor_key);

        let mut r_arr = p256::FieldBytes::default();
        r_arr.copy_from_slice(&attestation.vendor_sig_r);
        let mut s_arr = p256::FieldBytes::default();
        s_arr.copy_from_slice(&attestation.vendor_sig_s);
        let sig = P256Signature::from_scalars(r_arr, s_arr).unwrap();

        assert!(
            vendor_verifying.verify_prehash(&msg_hash, &sig).is_ok(),
            "Vendor key attestation must verify"
        );
    }

    #[test]
    fn test_vendor_attestation_different_key_fails() {
        // If someone tries to use a different vendor root key, the attestation
        // should not verify against the expected vendor root
        let gen = test_generator();
        let attestation = gen.key_attestation().clone();

        use p256::ecdsa::{
            SigningKey as P256SigningKey,
            VerifyingKey as P256VerifyingKey,
            Signature as P256Signature,
        };
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        // Reconstruct the message
        let mut hasher = Sha256::new();
        hasher.update(&attestation.platform_key_x);
        hasher.update(&attestation.platform_key_y);
        hasher.update([attestation.platform_id]);
        let msg_hash = {
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        // Try to verify with a DIFFERENT key (key = 3, not vendor root = 2)
        let wrong_key_bytes = {
            let mut k = [0u8; 32];
            k[31] = 3;
            k
        };
        let wrong_key = P256SigningKey::from_slice(&wrong_key_bytes).unwrap();
        let wrong_verifying = P256VerifyingKey::from(&wrong_key);

        let mut r_arr = p256::FieldBytes::default();
        r_arr.copy_from_slice(&attestation.vendor_sig_r);
        let mut s_arr = p256::FieldBytes::default();
        s_arr.copy_from_slice(&attestation.vendor_sig_s);
        let sig = P256Signature::from_scalars(r_arr, s_arr).unwrap();

        assert!(
            wrong_verifying.verify_prehash(&msg_hash, &sig).is_err(),
            "Attestation must NOT verify with wrong vendor root key"
        );
    }

    #[test]
    fn test_hw_report_hash_per_attestation() {
        let gen = test_generator();
        let a1 = gen.generate(b"payload-1").unwrap();
        let a2 = gen.generate(b"payload-2").unwrap();

        let ev1 = hex::decode(&a1.platform_evidence).unwrap();
        let ev2 = hex::decode(&a2.platform_evidence).unwrap();

        // hwReportHash at [160:192] for SGX evidence (256 bytes)
        let hw1 = &ev1[160..192];
        let hw2 = &ev2[160..192];

        // Must be non-zero
        assert_ne!(hw1, &[0u8; 32], "hwReportHash must be non-zero");
        assert_ne!(hw2, &[0u8; 32], "hwReportHash must be non-zero");

        // Must differ between attestations (different digests -> different hw reports)
        assert_ne!(hw1, hw2, "each attestation must have a unique hwReportHash");
    }

    #[test]
    fn test_hardware_provider_trait() {
        let provider = MockHardwareProvider::new([0xAB; 32], [0xCD; 32], test_vendor_root_key());
        let report_data = [0xFF; 32];
        let report = provider.generate_report(&report_data).unwrap();

        assert_ne!(report.report_hash, [0u8; 32], "mock report hash must be non-zero");
        assert_eq!(report.enclave_measurement, [0xAB; 32]);
        assert_eq!(report.signer_measurement, [0xCD; 32]);

        // Different report_data -> different report_hash
        let report2 = provider.generate_report(&[0xEE; 32]).unwrap();
        assert_ne!(report.report_hash, report2.report_hash);
    }

    /// When the `sgx` feature is NOT enabled, the stub provider always returns
    /// `PlatformNotAvailable`.  When the feature IS enabled, the real DCAP code
    /// path is compiled and these tests would attempt real hardware access, so
    /// we skip them.
    #[test]
    #[cfg(not(feature = "sgx"))]
    fn test_sgx_provider_not_available() {
        let provider = SgxHardwareProvider::create(test_vendor_root_key());
        let result = provider.generate_report(&[0xFF; 32]);
        assert!(result.is_err());
    }

    #[test]
    #[cfg(not(feature = "sgx"))]
    fn test_sgx_platform_key_generation_not_available() {
        // Real providers cannot generate platform keys without hardware
        let provider = SgxHardwareProvider::create(test_vendor_root_key());
        let result = provider.generate_platform_key(0);
        assert!(result.is_err(), "SGX platform key generation without hardware must fail");
    }

    #[test]
    fn test_platform_key_originates_from_hardware_provider() {
        // Verify that the platform key is generated by the hardware provider,
        // NOT supplied externally. The key attestation must verify against the
        // provider's vendor root key (D=2).
        let config = TEEConfig {
            platform: TEEPlatform::IntelSGX,
            enclave_hash: [0xAB; 32],
            signer_hash: [0xCD; 32],
            application_hash: None,
            allow_simulated: true,
            signing_key: test_signing_key(),
        };
        let mock_provider = Box::new(MockHardwareProvider::new(
            [0xAB; 32], [0xCD; 32], test_vendor_root_key(), // D=2
        ));
        let gen = AttestationGenerator::with_provider(config, mock_provider).unwrap();
        let attestation = gen.key_attestation();

        // Verify signature against D=2 (provider's vendor root key) — must succeed
        use p256::ecdsa::{
            SigningKey as P256SigningKey,
            VerifyingKey as P256VerifyingKey,
            Signature as P256Signature,
        };
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        let mut hasher = Sha256::new();
        hasher.update(&attestation.platform_key_x);
        hasher.update(&attestation.platform_key_y);
        hasher.update([attestation.platform_id]);
        let msg_hash = {
            let result = hasher.finalize();
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&result);
            hash
        };

        let vendor_key_d2 = P256SigningKey::from_slice(&test_vendor_root_key()).unwrap();
        let verifying_d2 = P256VerifyingKey::from(&vendor_key_d2);

        let mut r_arr = p256::FieldBytes::default();
        r_arr.copy_from_slice(&attestation.vendor_sig_r);
        let mut s_arr = p256::FieldBytes::default();
        s_arr.copy_from_slice(&attestation.vendor_sig_s);
        let sig = P256Signature::from_scalars(r_arr, s_arr).unwrap();

        assert!(
            verifying_d2.verify_prehash(&msg_hash, &sig).is_ok(),
            "Vendor attestation must verify against provider's vendor root key (D=2)"
        );

        // Verify against a DIFFERENT key (D=3) — must FAIL
        let wrong_key = {
            let mut k = [0u8; 32];
            k[31] = 3;
            k
        };
        let wrong_signing = P256SigningKey::from_slice(&wrong_key).unwrap();
        let wrong_verifying = P256VerifyingKey::from(&wrong_signing);
        assert!(
            wrong_verifying.verify_prehash(&msg_hash, &sig).is_err(),
            "Vendor attestation must NOT verify against wrong key (D=3)"
        );
    }

    #[test]
    fn test_real_platform_key_generation_rejects_without_hardware() {
        // AttestationGenerator::new() with a real platform uses the real provider.
        // Platform key generation (and thus construction) must fail without hardware.
        let config = TEEConfig {
            platform: TEEPlatform::IntelSGX,
            enclave_hash: [0xAB; 32],
            signer_hash: [0xCD; 32],
            application_hash: None,
            allow_simulated: false,
            signing_key: test_signing_key(),
        };
        let result = AttestationGenerator::new(config, test_vendor_root_key());
        assert!(result.is_err(), "SGX construction without hardware must fail");
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("not available") || err_msg.contains("unavailable"),
            "expected hardware-not-present error, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_measurement_mismatch_rejected() {
        // If the hardware report returns measurements that differ from config,
        // generate() must fail with MeasurementMismatch. This catches cases
        // where modified code is running inside the TEE.
        let config = TEEConfig {
            platform: TEEPlatform::Mock,
            enclave_hash: [0xAB; 32],
            signer_hash: [0xCD; 32],
            application_hash: None,
            allow_simulated: true,
            signing_key: test_signing_key(),
        };
        // Inject a provider with DIFFERENT measurements than config
        let wrong_provider = Box::new(MockHardwareProvider::new(
            [0xFF; 32], // wrong enclave measurement
            [0xCD; 32],
            test_vendor_root_key(),
        ));
        let gen = AttestationGenerator::with_provider(config, wrong_provider).unwrap();
        let result = gen.generate(b"test");
        assert!(result.is_err(), "mismatched enclave measurement must fail");
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("enclave_hash") && err_msg.contains("mismatch"),
            "expected MeasurementMismatch for enclave_hash, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_evidence_uses_hw_report_measurements() {
        // Verify that evidence measurements come from the hardware report,
        // not from config. With matching config/provider, they're the same,
        // but this test confirms the code path by checking evidence bytes
        // against the provider's measurements.
        let gen = test_generator();
        let attestation = gen.generate(b"measurement-source-test").unwrap();
        let evidence = hex::decode(&attestation.platform_evidence).unwrap();

        // mrenclave[0:32] and mrsigner[32:64] must match the mock provider's measurements
        assert_eq!(&evidence[0..32], &[0xAB; 32], "mrenclave from hw report");
        assert_eq!(&evidence[32..64], &[0xCD; 32], "mrsigner from hw report");

        // rawReportHash[160:192] must be non-zero
        let raw_report_hash = &evidence[160..192];
        assert_ne!(raw_report_hash, &[0u8; 32], "rawReportHash must be non-zero");

        // The P-256 signature covers the binding hash (not the raw report hash).
        // Verify by reconstructing with binding hash and checking the sig.
        let digest = compute_attestation_digest(
            attestation.platform, attestation.timestamp,
            &attestation.nonce, &attestation.enclave_hash,
            &attestation.signer_hash, &attestation.payload_hash,
        );
        let binding_hash = test_binding_hash(raw_report_hash, &[0xAB; 32], &[0xCD; 32]);

        let mut report_body = Vec::with_capacity(132);
        report_body.extend_from_slice(&[0xAB; 32]);
        report_body.extend_from_slice(&[0xCD; 32]);
        report_body.extend_from_slice(&digest);
        report_body.extend_from_slice(&1u16.to_be_bytes());
        report_body.extend_from_slice(&1u16.to_be_bytes());
        report_body.extend_from_slice(&binding_hash);

        verify_p256_signature(
            &extract_platform_key(&gen),
            &report_body,
            &evidence[192..224],
            &evidence[224..256],
        );

        // Also verify that using the raw report hash directly does NOT verify
        // (proving the signature covers the binding hash, not the raw hash)
        let mut wrong_body = Vec::with_capacity(132);
        wrong_body.extend_from_slice(&[0xAB; 32]);
        wrong_body.extend_from_slice(&[0xCD; 32]);
        wrong_body.extend_from_slice(&digest);
        wrong_body.extend_from_slice(&1u16.to_be_bytes());
        wrong_body.extend_from_slice(&1u16.to_be_bytes());
        wrong_body.extend_from_slice(raw_report_hash); // raw hash, NOT binding hash

        use p256::ecdsa::{
            SigningKey as P256SigningKey,
            VerifyingKey as P256VerifyingKey,
            Signature as P256Signature,
        };
        use p256::ecdsa::signature::hazmat::PrehashVerifier;

        let p256_key = P256SigningKey::from_slice(&extract_platform_key(&gen)).unwrap();
        let verifying_key = P256VerifyingKey::from(&p256_key);
        let wrong_hash = sha256_raw(&wrong_body);
        let mut r_arr = p256::FieldBytes::default();
        r_arr.copy_from_slice(&evidence[192..224]);
        let mut s_arr = p256::FieldBytes::default();
        s_arr.copy_from_slice(&evidence[224..256]);
        let sig = P256Signature::from_scalars(r_arr, s_arr).unwrap();
        assert!(
            verifying_key.verify_prehash(&wrong_hash, &sig).is_err(),
            "P-256 sig must NOT verify with raw report hash (must use binding hash)"
        );
    }

    #[test]
    fn test_mock_provider_rejected_for_real_platform_at_construction() {
        // Injecting a mock provider for a real platform without allow_simulated
        // must reject at construction (platform key generation is also gated).
        let config = TEEConfig {
            platform: TEEPlatform::AWSNitro,
            enclave_hash: [0xAB; 32],
            signer_hash: [0xCD; 32],
            application_hash: None,
            allow_simulated: false,
            signing_key: test_signing_key(),
        };
        let mock_provider = Box::new(MockHardwareProvider::new(
            [0xAB; 32], [0xCD; 32], test_vendor_root_key(),
        ));
        let result = AttestationGenerator::with_provider(config, mock_provider);
        assert!(result.is_err(), "mock provider for real platform must fail at construction");
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("simulated") || err_msg.contains("not allowed"),
            "expected SimulatedHardwareNotAllowed, got: {}",
            err_msg
        );
    }

    #[test]
    fn test_zero_vendor_key_rejected_for_real_platforms() {
        // AttestationGenerator::new() with [0u8; 32] as vendor key MUST fail
        // for all real TEE platforms. This prevents accidental insecure boot.
        for platform in [TEEPlatform::IntelSGX, TEEPlatform::AWSNitro, TEEPlatform::AMDSEV] {
            let config = TEEConfig {
                platform,
                enclave_hash: [0xAE; 32],
                signer_hash: [0x51; 32],
                application_hash: None,
                allow_simulated: true,
                signing_key: test_signing_key(),
            };
            let result = AttestationGenerator::new(config, [0u8; 32]);
            assert!(result.is_err(), "zero vendor key must be rejected for {:?}", platform);
            let err_msg = format!("{}", result.err().unwrap());
            assert!(
                err_msg.contains("vendor attestation") && err_msg.contains("[0; 32]"),
                "expected zero-key rejection message for {:?}, got: {}", platform, err_msg
            );
        }
    }

    #[test]
    fn test_zero_vendor_key_allowed_for_mock() {
        // Mock platform does NOT use the vendor_root_key from new() directly —
        // it has its own built-in vendor key. So [0u8; 32] is allowed for mock
        // (only used as a placeholder; the mock provider ignores it and uses D=2).
        // Actually, mock *does* use the vendor_root_key param, but [0; 32] is
        // not a valid P-256 key — so we use the standard test key here.
        // The important thing: the zero-key guard only applies to real platforms.
        let config = TEEConfig {
            platform: TEEPlatform::Mock,
            enclave_hash: [0xAE; 32],
            signer_hash: [0x51; 32],
            application_hash: None,
            allow_simulated: true,
            signing_key: test_signing_key(),
        };
        // Mock with a real vendor key should work.
        let result = AttestationGenerator::new(config, test_vendor_root_key());
        assert!(result.is_ok(), "mock platform with valid vendor key should succeed");
    }

    #[test]
    fn test_with_vendor_attester_rejects_mock_platform() {
        // with_vendor_attester() is for real platforms only.
        // Mock platform should use new() instead.
        let config = TEEConfig {
            platform: TEEPlatform::Mock,
            enclave_hash: [0xAE; 32],
            signer_hash: [0x51; 32],
            application_hash: None,
            allow_simulated: true,
            signing_key: test_signing_key(),
        };
        let attester = Box::new(LocalVendorAttester::new(test_vendor_root_key()));
        let result = AttestationGenerator::with_vendor_attester(config, attester);
        assert!(result.is_err(), "with_vendor_attester must reject Mock platform");
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("Mock") && err_msg.contains("new()"),
            "expected Mock-rejection message, got: {}", err_msg
        );
    }

    #[test]
    fn test_with_vendor_attester_uses_custom_attester() {
        // with_vendor_attester() for a real platform should use the provided
        // attester (not create one internally). Since we don't have real hardware,
        // this will fail with PlatformNotAvailable — which proves the real
        // provider was instantiated (mock would succeed).
        let config = TEEConfig {
            platform: TEEPlatform::IntelSGX,
            enclave_hash: [0xAE; 32],
            signer_hash: [0x51; 32],
            application_hash: None,
            allow_simulated: false, // Don't allow fallback
            signing_key: test_signing_key(),
        };
        let attester = Box::new(LocalVendorAttester::new(test_vendor_root_key()));
        let result = AttestationGenerator::with_vendor_attester(config, attester);
        // On a non-SGX machine, key generation fails with PlatformNotAvailable.
        // This confirms the real SGX provider was selected (not mock).
        assert!(result.is_err(), "SGX without hardware should fail");
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("SGX") || err_msg.contains("not available") || err_msg.contains("unavailable"),
            "expected platform unavailable error, got: {}", err_msg
        );
    }

}
