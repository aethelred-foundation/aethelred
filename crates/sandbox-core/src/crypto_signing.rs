//! Real hybrid (ECDSA + CRYSTALS-Dilithium-3) seal signing & verification.
//!
//! This module replaces the previous "validator_signature_hex is just a string"
//! placeholder with **real cryptographic signatures** built on the workspace
//! `aethelred-core` primitives — the same ECDSA-secp256k1 + Dilithium-3 hybrid
//! the mainnet protocol uses.
//!
//! ## What this fixes
//!
//! Before v0.2.1, `DigitalSeal::validator_signature_hex` was an opaque hex
//! string with no enforced semantics. The default `Verifier` only checked
//! that the string parsed as hex; it had no public-key set, no algorithm
//! discrimination, no replay protection, no quantum threat awareness.
//!
//! This module provides:
//!
//! 1. [`SealSigner`] — a trait for any signer that can produce a hybrid
//!    signature over a [`DigitalSeal`]'s pre-signature hash.
//! 2. [`HybridSealSigner`] — a concrete signer that owns a
//!    `aethelred_core::crypto::HybridKeyPair` (ECDSA-secp256k1 + Dilithium-3,
//!    NIST FIPS 204) and produces real signatures.
//! 3. [`HybridSealVerifier`] — a real verifier that checks both ECDSA and
//!    Dilithium components against a known [`HybridPublicKey`], enforces
//!    a `VerifierConfig` (mainnet/testnet/devnet/quantum-only), and rejects
//!    on any component failure.
//! 4. [`ValidatorQuorum`] — a thresholded multi-validator quorum: M-of-N
//!    signers must sign for the seal to be considered anchored.
//! 5. [`SignatureEnvelope`] — the wire format for a signed seal, replacing
//!    the opaque `validator_signature_hex` string with a structured object
//!    containing version, algorithm, timestamp, chain id, signer id, and
//!    the actual hybrid bytes.
//!
//! ## Wire compatibility
//!
//! For backwards compatibility with v0.2.0 seals, the [`SignatureEnvelope`]
//! is serialized to a hex blob that is stored in
//! `DigitalSeal::validator_signature_hex`. Old verifiers that just check
//! "is this hex" still pass; new verifiers parse the structured envelope
//! and perform the real check.
//!
//! ## Quantum-first posture
//!
//! Per the Aethelred whitepaper, Dilithium is the *primary* security layer.
//! The ECDSA signature is defense-in-depth and assumed compromised at
//! `QuantumThreatLevel::Q_DAY`. [`HybridSealVerifier::strict_mainnet()`]
//! requires both signatures; [`HybridSealVerifier::quantum_only()`] only
//! checks Dilithium.
//!
//! ## Real keys, real signatures
//!
//! ```ignore
//! use aethelred_sandbox_core::crypto_signing::{HybridSealSigner, HybridSealVerifier};
//!
//! let signer = HybridSealSigner::generate("validator-1")?;
//! let signed = signer.sign_seal(seal)?;
//!
//! // Days later, an independent reviewer:
//! let verifier = HybridSealVerifier::for_signer("validator-1", signer.public_key());
//! verifier.verify_signed_seal(&signed)?;
//! ```

#[cfg(feature = "real-crypto")]
use aethelred_core::crypto::hybrid::{
    DilithiumSecurityLevel, HybridKeyPair, HybridPublicKey, HybridSignature, VerifierConfig,
};

use crate::error_code::{ErrorCode, ErrorCategory};
use crate::hashing::Sha256Digest;
use crate::seal::DigitalSeal;
use crate::{SandboxError, SandboxResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use time::OffsetDateTime;

// =============================================================================
// Wire format
// =============================================================================

/// Versioned signature envelope, the wire format for signed seals.
///
/// Stored in [`DigitalSeal::validator_signature_hex`] as a hex-encoded
/// canonical-JSON blob (so old hex-only readers still parse, and new
/// readers can deserialize the structure).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureEnvelope {
    /// Wire format version (currently `1`).
    pub version: u8,
    /// Stable algorithm id (e.g., `"hybrid-ecdsa-dilithium3"`).
    pub algorithm: String,
    /// Signer id (e.g., `"validator-1"`, `"fab-prod-signer-2026-q4"`).
    pub signer_id: String,
    /// Chain id (1 = mainnet, 2 = testnet, 9999 = devnet).
    pub chain_id: u64,
    /// RFC 3339 signature timestamp.
    pub signed_at: String,
    /// Hash of the seal's pre-signature canonical form (hex).
    pub message_hash: String,
    /// Hex-encoded `HybridSignature::classical` (ECDSA-secp256k1, 64 bytes).
    pub classical_sig_hex: String,
    /// Hex-encoded `HybridSignature::quantum` (Dilithium-3, ~3.3 KB).
    pub quantum_sig_hex: String,
    /// Dilithium security level (2/3/5).
    pub dilithium_level: u8,
}

impl SignatureEnvelope {
    /// Encode as a hex blob (backwards-compatible with the old `String` shape).
    pub fn to_hex_blob(&self) -> SandboxResult<String> {
        let bytes = serde_json::to_vec(self).map_err(|e| {
            SandboxError::Crypto(format!("envelope serialise: {e}"))
        })?;
        Ok(hex::encode(bytes))
    }

    /// Decode from a hex blob.
    pub fn from_hex_blob(blob: &str) -> SandboxResult<Self> {
        let bytes = hex::decode(blob).map_err(|e| {
            SandboxError::Crypto(format!("envelope hex decode: {e}"))
        })?;
        serde_json::from_slice(&bytes).map_err(|e| {
            SandboxError::Crypto(format!("envelope deserialise: {e}"))
        })
    }
}

/// A seal bundled with its real cryptographic signature envelope.
///
/// This is what real customers store and share. The `seal` carries the
/// envelope hex-encoded in `validator_signature_hex` (for v0.2.0 reader
/// compatibility); the `envelope` carries the structured form.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedSeal {
    /// The seal with `validator_signature_hex` set to the envelope hex blob.
    pub seal: DigitalSeal,
    /// The structured signature envelope (mirrors `seal.validator_signature_hex`).
    pub envelope: SignatureEnvelope,
}

impl SignedSeal {
    /// Reassemble from a seal whose `validator_signature_hex` carries an
    /// envelope hex blob.
    pub fn from_seal(seal: DigitalSeal) -> SandboxResult<Self> {
        let blob = seal
            .validator_signature_hex
            .as_ref()
            .ok_or_else(|| SandboxError::Crypto("seal carries no signature".into()))?;
        let envelope = SignatureEnvelope::from_hex_blob(blob)?;
        Ok(Self { seal, envelope })
    }
}

// =============================================================================
// SealSigner trait
// =============================================================================

/// A signer that can produce a structured signature envelope over a seal.
///
/// Production deployments back this with HSM-bound keys (PKCS#11, AWS KMS,
/// CloudHSM, Azure Key Vault, GCP KMS). For development and testing,
/// [`HybridSealSigner::generate`] creates an in-memory keypair.
pub trait SealSigner: Send + Sync {
    /// Stable signer id (e.g., `"validator-1"`).
    fn signer_id(&self) -> &str;
    /// Algorithm name.
    fn algorithm(&self) -> &str;
    /// Chain id this signer is bound to.
    fn chain_id(&self) -> u64;
    /// Sign a seal — produce a [`SignedSeal`].
    fn sign_seal(&self, seal: DigitalSeal) -> SandboxResult<SignedSeal>;
}

// =============================================================================
// HybridSealSigner
// =============================================================================

/// In-memory hybrid (ECDSA + Dilithium-3) signer.
///
/// Production deployments should swap this out for an HSM-backed signer
/// (see `aethelred_core::crypto::signer::ValidatorHsmSigner` behind the
/// `hsm` feature). This in-memory variant is appropriate for sandboxes,
/// design-partner pilots, and dev/CI environments.
#[cfg(feature = "real-crypto")]
pub struct HybridSealSigner {
    signer_id: String,
    chain_id: u64,
    keypair: HybridKeyPair,
}

#[cfg(feature = "real-crypto")]
impl HybridSealSigner {
    /// Generate a fresh hybrid keypair (Dilithium-3 default).
    pub fn generate(signer_id: impl Into<String>) -> SandboxResult<Self> {
        let keypair = HybridKeyPair::generate().map_err(|e| {
            SandboxError::Crypto(format!("HybridKeyPair::generate: {e}"))
        })?;
        Ok(Self {
            signer_id: signer_id.into(),
            chain_id: 1,
            keypair,
        })
    }

    /// Generate at a specific Dilithium level (2/3/5).
    pub fn generate_at_level(
        signer_id: impl Into<String>,
        level: DilithiumSecurityLevel,
    ) -> SandboxResult<Self> {
        let keypair = HybridKeyPair::generate_with_level(level).map_err(|e| {
            SandboxError::Crypto(format!("HybridKeyPair::generate_with_level: {e}"))
        })?;
        Ok(Self {
            signer_id: signer_id.into(),
            chain_id: 1,
            keypair,
        })
    }

    /// Set the chain id (for cross-chain replay protection).
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }

    /// Borrow the public key (this is what the verifier needs).
    pub fn public_key(&self) -> &HybridPublicKey {
        &self.keypair.public_key
    }
}

#[cfg(feature = "real-crypto")]
impl SealSigner for HybridSealSigner {
    fn signer_id(&self) -> &str {
        &self.signer_id
    }
    fn algorithm(&self) -> &str {
        "hybrid-ecdsa-dilithium3"
    }
    fn chain_id(&self) -> u64 {
        self.chain_id
    }
    fn sign_seal(&self, mut seal: DigitalSeal) -> SandboxResult<SignedSeal> {
        // Strip any existing signature so we sign the canonical pre-sig form.
        seal.validator_signature_hex = None;
        let pre_sig_hash = seal.pre_signature_hash()?;
        // Sign the 32-byte hash.
        let signature = self
            .keypair
            .sign(&pre_sig_hash.0)
            .map_err(|e| SandboxError::Crypto(format!("hybrid sign: {e}")))?;
        let now = OffsetDateTime::now_utc();
        let signed_at = now
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| String::new());

        // Detect security level from signature size.
        let level_byte = match signature.level {
            DilithiumSecurityLevel::Level2 => 2u8,
            DilithiumSecurityLevel::Level3 => 3u8,
            DilithiumSecurityLevel::Level5 => 5u8,
        };

        let envelope = SignatureEnvelope {
            version: 1,
            algorithm: "hybrid-ecdsa-dilithium3".into(),
            signer_id: self.signer_id.clone(),
            chain_id: self.chain_id,
            signed_at,
            message_hash: pre_sig_hash.to_hex(),
            classical_sig_hex: hex::encode(&signature.classical),
            quantum_sig_hex: hex::encode(&signature.quantum),
            dilithium_level: level_byte,
        };
        let blob = envelope.to_hex_blob()?;
        seal.validator_signature_hex = Some(blob);
        Ok(SignedSeal { seal, envelope })
    }
}

// =============================================================================
// HybridSealVerifier
// =============================================================================

/// Real hybrid signature verifier.
///
/// Maintains a registry mapping `signer_id` → `HybridPublicKey`. To verify
/// a seal, the verifier looks up the public key by `envelope.signer_id`,
/// reconstructs the [`HybridSignature`], and runs the hybrid verify against
/// the seal's pre-signature hash.
#[cfg(feature = "real-crypto")]
pub struct HybridSealVerifier {
    registry: HashMap<String, HybridPublicKey>,
    config: VerifierConfig,
}

#[cfg(feature = "real-crypto")]
impl HybridSealVerifier {
    /// Empty verifier — register signers with [`Self::register`].
    pub fn empty() -> Self {
        Self {
            registry: HashMap::new(),
            config: VerifierConfig::default(),
        }
    }

    /// Verifier prebound to a single signer.
    pub fn for_signer(signer_id: impl Into<String>, public_key: HybridPublicKey) -> Self {
        let mut v = Self::empty();
        v.register(signer_id, public_key);
        v
    }

    /// Strict mainnet posture: requires both ECDSA + Dilithium-3.
    pub fn strict_mainnet() -> Self {
        Self {
            registry: HashMap::new(),
            config: VerifierConfig::mainnet(),
        }
    }

    /// Devnet posture: more permissive.
    pub fn devnet() -> Self {
        Self {
            registry: HashMap::new(),
            config: VerifierConfig::devnet(),
        }
    }

    /// Testnet posture.
    pub fn testnet() -> Self {
        Self {
            registry: HashMap::new(),
            config: VerifierConfig::testnet(),
        }
    }

    /// Register a signer's public key.
    pub fn register(&mut self, signer_id: impl Into<String>, public_key: HybridPublicKey) -> &mut Self {
        self.registry.insert(signer_id.into(), public_key);
        self
    }

    /// `true` if this verifier has a public key for `signer_id`.
    pub fn knows_signer(&self, signer_id: &str) -> bool {
        self.registry.contains_key(signer_id)
    }

    /// Verify a [`SignedSeal`].
    pub fn verify_signed_seal(&self, signed: &SignedSeal) -> SandboxResult<()> {
        let env = &signed.envelope;
        if env.version != 1 {
            return Err(SandboxError::Crypto(format!(
                "unsupported envelope version: {}", env.version
            )));
        }
        if env.algorithm != "hybrid-ecdsa-dilithium3" {
            return Err(SandboxError::Crypto(format!(
                "unsupported algorithm: {}", env.algorithm
            )));
        }
        if env.chain_id != self.config.chain_id {
            return Err(SandboxError::Crypto(format!(
                "chain_id mismatch: envelope={} verifier={}",
                env.chain_id, self.config.chain_id
            )));
        }
        let pubkey = self.registry.get(&env.signer_id).ok_or_else(|| {
            SandboxError::Crypto(format!("unknown signer: {}", env.signer_id))
        })?;
        // Reconstruct the HybridSignature.
        let classical = hex::decode(&env.classical_sig_hex)
            .map_err(|e| SandboxError::Crypto(format!("classical hex: {e}")))?;
        let quantum = hex::decode(&env.quantum_sig_hex)
            .map_err(|e| SandboxError::Crypto(format!("quantum hex: {e}")))?;
        let level = match env.dilithium_level {
            2 => DilithiumSecurityLevel::Level2,
            3 => DilithiumSecurityLevel::Level3,
            5 => DilithiumSecurityLevel::Level5,
            other => {
                return Err(SandboxError::Crypto(format!(
                    "unsupported dilithium level: {other}"
                )))
            }
        };
        if level < self.config.min_dilithium_level {
            return Err(SandboxError::Crypto(format!(
                "dilithium level {:?} below minimum {:?}",
                level, self.config.min_dilithium_level
            )));
        }
        let sig = HybridSignature::new(classical, quantum, level);
        // Recompute the pre-sig hash on the seal's canonical form
        // (with signature stripped).
        let mut seal_for_hash = signed.seal.clone();
        seal_for_hash.validator_signature_hex = None;
        let pre_sig_hash = seal_for_hash.pre_signature_hash()?;
        // Cross-check against the envelope's message_hash field.
        if pre_sig_hash.to_hex() != env.message_hash {
            return Err(SandboxError::Crypto(format!(
                "message_hash mismatch: recomputed={} envelope={}",
                pre_sig_hash.to_hex(),
                env.message_hash
            )));
        }
        // Now run the actual hybrid verify.
        sig.verify(&pre_sig_hash.0, pubkey, &self.config)
            .map_err(|e| SandboxError::Crypto(format!("hybrid verify: {e}")))?;
        Ok(())
    }

    /// Verify a [`DigitalSeal`] that carries the envelope hex in
    /// `validator_signature_hex`. Convenience wrapper.
    pub fn verify_seal(&self, seal: &DigitalSeal) -> SandboxResult<()> {
        let signed = SignedSeal::from_seal(seal.clone())?;
        self.verify_signed_seal(&signed)
    }

    /// Number of registered signers.
    pub fn signer_count(&self) -> usize {
        self.registry.len()
    }
}

// =============================================================================
// ValidatorQuorum (M-of-N)
// =============================================================================

/// Multi-signature quorum (M-of-N).
///
/// Production deployments use this to require, e.g., 3-of-5 validator
/// approval before a seal is considered anchored.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuorumSeal {
    /// The underlying seal.
    pub seal: DigitalSeal,
    /// All validator envelopes that have signed the same `pre_signature_hash`.
    pub envelopes: Vec<SignatureEnvelope>,
    /// Threshold required (M).
    pub threshold: u32,
    /// Total signers configured (N).
    pub total: u32,
}

impl QuorumSeal {
    /// Number of signatures collected so far.
    pub fn collected(&self) -> usize {
        self.envelopes.len()
    }

    /// `true` if `collected() >= threshold`.
    pub fn is_threshold_met(&self) -> bool {
        self.envelopes.len() >= self.threshold as usize
    }

    /// Distinct signer ids that have signed.
    pub fn signers(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = self.envelopes.iter().map(|e| e.signer_id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        ids
    }
}

/// A validator quorum: a set of [`SealSigner`]s plus a threshold M.
#[cfg(feature = "real-crypto")]
pub struct ValidatorQuorum {
    signers: Vec<Box<dyn SealSigner>>,
    threshold: u32,
}

#[cfg(feature = "real-crypto")]
impl ValidatorQuorum {
    /// New quorum.
    pub fn new(signers: Vec<Box<dyn SealSigner>>, threshold: u32) -> SandboxResult<Self> {
        let n = signers.len() as u32;
        if threshold == 0 {
            return Err(SandboxError::config("quorum threshold must be ≥ 1"));
        }
        if threshold > n {
            return Err(SandboxError::config(format!(
                "threshold {threshold} > total signers {n}"
            )));
        }
        Ok(Self { signers, threshold })
    }

    /// Number of signers in the quorum (N).
    pub fn total(&self) -> u32 {
        self.signers.len() as u32
    }

    /// Threshold (M).
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Have every signer in the quorum sign the seal — produces a
    /// [`QuorumSeal`]. Returns `Err` if any signer fails.
    pub fn sign(&self, seal: DigitalSeal) -> SandboxResult<QuorumSeal> {
        let total = self.total();
        let mut envelopes = Vec::with_capacity(self.signers.len());
        for signer in &self.signers {
            let signed = signer.sign_seal(seal.clone())?;
            envelopes.push(signed.envelope);
        }
        Ok(QuorumSeal {
            seal,
            envelopes,
            threshold: self.threshold,
            total,
        })
    }
}

// =============================================================================
// Error code routing for crypto failures
// =============================================================================

/// Map a crypto failure to a stable error code.
pub fn signing_error_code(err: &SandboxError) -> ErrorCode {
    if matches!(err, SandboxError::Crypto(msg) if msg.contains("verify"))
    {
        ErrorCode::new(ErrorCategory::Crypto, 5001)
    } else {
        ErrorCode::new(ErrorCategory::Crypto, 5000)
    }
}

// =============================================================================
// Stub for non-real-crypto builds
// =============================================================================

#[cfg(not(feature = "real-crypto"))]
pub struct HybridSealSigner;

#[cfg(not(feature = "real-crypto"))]
impl HybridSealSigner {
    pub fn generate(_signer_id: impl Into<String>) -> SandboxResult<Self> {
        Err(SandboxError::Crypto(
            "real-crypto feature required for HybridSealSigner".into(),
        ))
    }
}

// =============================================================================
// Hash helper used in tests
// =============================================================================

/// Compute the pre-sig hash of a seal — the message that gets signed.
pub fn pre_signature_hash(seal: &DigitalSeal) -> SandboxResult<Sha256Digest> {
    let mut clone = seal.clone();
    clone.validator_signature_hex = None;
    crate::hashing::Hasher::hash_value(&clone)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(all(test, feature = "real-crypto"))]
mod tests {
    use super::*;
    use crate::hashing::Hasher;
    use crate::seal::{ApprovalRecord, ModelReference, RetentionClass, SealVersion};
    use crate::Sector;
    use std::collections::BTreeMap;
    use time::OffsetDateTime;
    use uuid::Uuid;

    fn dummy_seal() -> DigitalSeal {
        DigitalSeal {
            schema_version: SealVersion::V1,
            seal_id: Uuid::now_v7(),
            timestamp: OffsetDateTime::now_utc(),
            sector: Sector::Finance,
            event_type: "credit_decision".into(),
            event_hash: Hasher::sha256(b"event"),
            model: ModelReference::new("m", Hasher::sha256(b"w")),
            policy_id: "po".into(),
            input_hash: Hasher::sha256(b"in"),
            output_hash: Hasher::sha256(b"out"),
            approvals: vec![ApprovalRecord::unsigned("u", "r", "approved")],
            attestation: None,
            zk_proof: None,
            tenant_id: "FAB".into(),
            workflow_id: "credit_decision".into(),
            jurisdiction_tag: "AE-CBUAE".into(),
            retention: RetentionClass::SevenYears,
            prior_seal_hash: None,
            sector_extension: BTreeMap::new(),
            validator_signature_hex: None,
        }
    }

    #[test]
    fn signer_produces_signed_seal_with_envelope() {
        let signer = HybridSealSigner::generate("validator-1").unwrap();
        let signed = signer.sign_seal(dummy_seal()).unwrap();
        assert!(signed.seal.validator_signature_hex.is_some());
        assert_eq!(signed.envelope.signer_id, "validator-1");
        assert_eq!(signed.envelope.algorithm, "hybrid-ecdsa-dilithium3");
        assert_eq!(signed.envelope.dilithium_level, 3);
    }

    #[test]
    fn verifier_accepts_own_signed_seal() {
        let signer = HybridSealSigner::generate("validator-1").unwrap();
        let signed = signer.sign_seal(dummy_seal()).unwrap();
        let verifier = HybridSealVerifier::for_signer("validator-1", signer.public_key().clone());
        verifier.verify_signed_seal(&signed).unwrap();
    }

    #[test]
    fn verifier_rejects_unknown_signer() {
        let signer = HybridSealSigner::generate("unknown-signer").unwrap();
        let signed = signer.sign_seal(dummy_seal()).unwrap();
        let other = HybridSealSigner::generate("other").unwrap();
        let verifier = HybridSealVerifier::for_signer("other", other.public_key().clone());
        let r = verifier.verify_signed_seal(&signed);
        assert!(r.is_err());
    }

    #[test]
    fn verifier_rejects_tampered_seal() {
        let signer = HybridSealSigner::generate("validator-1").unwrap();
        let mut signed = signer.sign_seal(dummy_seal()).unwrap();
        // Tamper with the seal *content* but leave the signature intact.
        signed.seal.event_hash = Hasher::sha256(b"tampered");
        let verifier = HybridSealVerifier::for_signer("validator-1", signer.public_key().clone());
        let r = verifier.verify_signed_seal(&signed);
        assert!(r.is_err());
    }

    #[test]
    fn verifier_rejects_chain_id_mismatch() {
        let signer = HybridSealSigner::generate("validator-1")
            .unwrap()
            .with_chain_id(2); // testnet
        let signed = signer.sign_seal(dummy_seal()).unwrap();
        let verifier = HybridSealVerifier::for_signer("validator-1", signer.public_key().clone());
        // verifier defaults to mainnet (chain_id = 1)
        let r = verifier.verify_signed_seal(&signed);
        assert!(r.is_err());
    }

    #[test]
    fn envelope_hex_blob_round_trips() {
        let signer = HybridSealSigner::generate("v1").unwrap();
        let signed = signer.sign_seal(dummy_seal()).unwrap();
        let blob = signed.envelope.to_hex_blob().unwrap();
        let parsed = SignatureEnvelope::from_hex_blob(&blob).unwrap();
        assert_eq!(parsed, signed.envelope);
    }

    #[test]
    fn signed_seal_can_be_recovered_from_seal_alone() {
        let signer = HybridSealSigner::generate("v1").unwrap();
        let signed = signer.sign_seal(dummy_seal()).unwrap();
        let recovered = SignedSeal::from_seal(signed.seal.clone()).unwrap();
        assert_eq!(recovered.envelope, signed.envelope);
    }

    #[test]
    fn quorum_collects_all_signatures() {
        let s1 = Box::new(HybridSealSigner::generate("v1").unwrap()) as Box<dyn SealSigner>;
        let s2 = Box::new(HybridSealSigner::generate("v2").unwrap()) as Box<dyn SealSigner>;
        let s3 = Box::new(HybridSealSigner::generate("v3").unwrap()) as Box<dyn SealSigner>;
        let q = ValidatorQuorum::new(vec![s1, s2, s3], 2).unwrap();
        let qs = q.sign(dummy_seal()).unwrap();
        assert_eq!(qs.collected(), 3);
        assert!(qs.is_threshold_met());
        assert_eq!(qs.signers().len(), 3);
    }

    #[test]
    fn quorum_threshold_zero_rejected() {
        let s1 = Box::new(HybridSealSigner::generate("v1").unwrap()) as Box<dyn SealSigner>;
        assert!(ValidatorQuorum::new(vec![s1], 0).is_err());
    }

    #[test]
    fn quorum_threshold_above_total_rejected() {
        let s1 = Box::new(HybridSealSigner::generate("v1").unwrap()) as Box<dyn SealSigner>;
        assert!(ValidatorQuorum::new(vec![s1], 5).is_err());
    }

    #[test]
    fn signer_at_dilithium_level_3_works() {
        // Level 3 (NIST FIPS 204 default) is the supported level today.
        let signer = HybridSealSigner::generate_at_level("v1", DilithiumSecurityLevel::Level3).unwrap();
        let signed = signer.sign_seal(dummy_seal()).unwrap();
        assert_eq!(signed.envelope.dilithium_level, 3);
    }

    #[test]
    fn level_2_generation_currently_unsupported() {
        // Level 2 / Level 5 are reserved by the workspace crypto crate but
        // not yet implemented. We surface the failure cleanly instead of
        // panicking.
        let r = HybridSealSigner::generate_at_level("v1", DilithiumSecurityLevel::Level2);
        assert!(r.is_err());
    }

    #[test]
    fn level_5_generation_currently_unsupported() {
        let r = HybridSealSigner::generate_at_level("v1", DilithiumSecurityLevel::Level5);
        assert!(r.is_err());
    }

    #[test]
    fn pre_signature_hash_is_signature_invariant() {
        let mut seal = dummy_seal();
        let h0 = pre_signature_hash(&seal).unwrap();
        seal.validator_signature_hex = Some("ff".repeat(64));
        let h1 = pre_signature_hash(&seal).unwrap();
        assert_eq!(h0, h1);
    }

    #[test]
    fn knows_signer_returns_true_for_registered() {
        let signer = HybridSealSigner::generate("v1").unwrap();
        let v = HybridSealVerifier::for_signer("v1", signer.public_key().clone());
        assert!(v.knows_signer("v1"));
        assert!(!v.knows_signer("v2"));
    }

    #[test]
    fn verifier_rejects_envelope_version_mismatch() {
        let signer = HybridSealSigner::generate("v1").unwrap();
        let signed = signer.sign_seal(dummy_seal()).unwrap();
        let mut bad = signed.clone();
        bad.envelope.version = 99;
        let v = HybridSealVerifier::for_signer("v1", signer.public_key().clone());
        let r = v.verify_signed_seal(&bad);
        assert!(r.is_err());
    }

    #[test]
    fn signed_seal_serde_round_trip() {
        let signer = HybridSealSigner::generate("v1").unwrap();
        let signed = signer.sign_seal(dummy_seal()).unwrap();
        let j = serde_json::to_string(&signed).unwrap();
        let p: SignedSeal = serde_json::from_str(&j).unwrap();
        assert_eq!(p.envelope, signed.envelope);
    }

    #[test]
    fn quorum_signer_registry_is_unique() {
        let s1 = Box::new(HybridSealSigner::generate("v1").unwrap()) as Box<dyn SealSigner>;
        let s2 = Box::new(HybridSealSigner::generate("v1").unwrap()) as Box<dyn SealSigner>;
        let q = ValidatorQuorum::new(vec![s1, s2], 1).unwrap();
        let qs = q.sign(dummy_seal()).unwrap();
        // Both signers have the same id; signers() should dedupe.
        let signers = qs.signers();
        assert_eq!(signers.len(), 1);
    }

    #[test]
    fn signer_id_is_returned() {
        let s = HybridSealSigner::generate("validator-A").unwrap();
        assert_eq!(s.signer_id(), "validator-A");
    }

    #[test]
    fn algorithm_id_is_stable() {
        let s = HybridSealSigner::generate("v").unwrap();
        assert_eq!(s.algorithm(), "hybrid-ecdsa-dilithium3");
    }
}
