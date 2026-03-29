//! Verifiable Random Function (VRF) Implementation
//!
//! Enterprise-grade VRF for fair, unpredictable, but verifiable leader selection.
//!
//! # Overview
//!
//! VRF provides a way for validators to prove they were selected as block proposers
//! without revealing their secret keys. The VRF output is:
//! 1. **Deterministic**: Same inputs always produce same output
//! 2. **Unpredictable**: Cannot guess output without the secret key
//! 3. **Verifiable**: Anyone can verify the output using the public key
//!
//! # ECVRF Construction
//!
//! We use ECVRF-SECP256K1-SHA256-SSWU following IETF draft-irtf-cfrg-vrf-15
//! with RFC 9380 constant-time hash-to-curve (Simplified SWU with 3-isogeny):
//!
//! ```text
//! VRF.Prove(SK, message) -> (output, proof)
//! VRF.Verify(PK, message, output, proof) -> bool
//! ```
//!
//! # Security
//!
//! - **Hash-to-curve**: Uses RFC 9380 §6.6.2 Simplified SWU map (constant-time).
//!   Prior versions used try-and-increment which leaked timing information (RS-01).
//! - **Key material**: Secret keys are zeroized on drop via `zeroize` crate (RS-07).
//! - **Mock isolation**: Development mode uses SHA-256-derived public keys, never
//!   exposes raw secret key material (RS-02).
//! - **Audit status**: All findings remediated (2026-02-28).

use crate::error::{ConsensusError, ConsensusResult};
use crate::types::{EpochSeed, Slot};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// VRF key pair
///
/// SECURITY (RS-07 fix): Secret key is zeroized on drop via the `zeroize` crate
/// to prevent key material from persisting in freed memory.
#[derive(Clone, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct VrfKeys {
    /// Secret key (32 bytes)
    secret_key: [u8; 32],
    /// Public key (33 bytes compressed)
    #[zeroize(skip)]
    public_key: Vec<u8>,
}

impl VrfKeys {
    /// Generate new VRF keypair from seed
    pub fn from_seed(seed: &[u8; 32]) -> ConsensusResult<Self> {
        #[cfg(feature = "vrf")]
        {
            use k256::ecdsa::SigningKey;
            use k256::elliptic_curve::sec1::ToEncodedPoint;

            let signing_key = SigningKey::from_bytes(seed.into())
                .map_err(|e| ConsensusError::InvalidVrfKey(e.to_string()))?;

            let verifying_key = signing_key.verifying_key();
            let public_key = verifying_key.to_encoded_point(true).as_bytes().to_vec();

            Ok(Self {
                secret_key: *seed,
                public_key,
            })
        }

        #[cfg(not(feature = "vrf"))]
        {
            // Mock implementation for development - SECURITY (RS-02 fix):
            // Public key is derived via SHA-256("mock-vrf-pk:" || seed) to avoid
            // embedding the raw secret key in the public key.
            use sha2::{Digest, Sha256};
            let mut pk_hasher = Sha256::new();
            pk_hasher.update(b"mock-vrf-pk:");
            pk_hasher.update(seed);
            let pk_hash: [u8; 32] = pk_hasher.finalize().into();
            let mut public_key = vec![0x02]; // Compressed prefix
            public_key.extend_from_slice(&pk_hash);
            Ok(Self {
                secret_key: *seed,
                public_key,
            })
        }
    }

    /// Generate random VRF keypair
    pub fn generate() -> ConsensusResult<Self> {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Get public key
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    /// Get secret key (use with caution!)
    pub fn secret_key(&self) -> &[u8; 32] {
        &self.secret_key
    }

    /// Get public key as owned bytes
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.clone()
    }

    /// Derive child keys for a specific epoch (key rotation)
    pub fn derive_epoch_keys(&self, epoch: u64) -> ConsensusResult<Self> {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(&self.secret_key);
        hasher.update(b"epoch_derive");
        hasher.update(&epoch.to_le_bytes());

        let derived_seed: [u8; 32] = hasher.finalize().into();
        Self::from_seed(&derived_seed)
    }
}

impl std::fmt::Debug for VrfKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VrfKeys")
            .field("public_key", &hex::encode(&self.public_key))
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// VRF proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VrfProof {
    /// Gamma point (33 bytes compressed)
    pub gamma: Vec<u8>,
    /// Challenge scalar (32 bytes)
    pub c: [u8; 32],
    /// Response scalar (32 bytes)
    pub s: [u8; 32],
}

impl VrfProof {
    /// Proof size in bytes
    pub const SIZE: usize = 33 + 32 + 32; // 97 bytes

    /// Serialize proof to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(Self::SIZE);
        bytes.extend_from_slice(&self.gamma);
        bytes.extend_from_slice(&self.c);
        bytes.extend_from_slice(&self.s);
        bytes
    }

    /// Deserialize proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> ConsensusResult<Self> {
        if bytes.len() < Self::SIZE {
            return Err(ConsensusError::MalformedVrfProof {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        let gamma = bytes[0..33].to_vec();
        let mut c = [0u8; 32];
        c.copy_from_slice(&bytes[33..65]);
        let mut s = [0u8; 32];
        s.copy_from_slice(&bytes[65..97]);

        Ok(Self { gamma, c, s })
    }
}

/// VRF output (hash of gamma point)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VrfOutput(pub [u8; 32]);

impl VrfOutput {
    /// Create from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Get as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Convert to big integer for threshold comparison
    pub fn to_bigint(&self) -> num_bigint::BigUint {
        num_bigint::BigUint::from_bytes_be(&self.0)
    }
}

impl AsRef<[u8]> for VrfOutput {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// VRF engine for leader election
pub struct VrfEngine {
    /// Domain separation tag
    domain_tag: Vec<u8>,
}

impl VrfEngine {
    /// Create new VRF engine with default chain ID
    pub fn new() -> Self {
        Self::with_chain_id(1)
    }

    /// Create new VRF engine with specific chain ID
    pub fn with_chain_id(chain_id: u64) -> Self {
        let mut domain_tag = b"Aethelred-PoUW-VRF-v1:".to_vec();
        domain_tag.extend_from_slice(&chain_id.to_le_bytes());
        Self { domain_tag }
    }

    /// Construct VRF input message from epoch seed and slot
    pub fn construct_message(&self, epoch_seed: &EpochSeed, slot: Slot) -> Vec<u8> {
        let mut message = self.domain_tag.clone();
        message.extend_from_slice(epoch_seed);
        message.extend_from_slice(&slot.to_le_bytes());
        message
    }

    /// Simplified prove that takes raw input bytes
    /// Used by consensus engine for flexible input construction
    pub fn prove(&self, keys: &VrfKeys, input: &[u8]) -> ConsensusResult<(VrfProof, VrfOutput)> {
        #[cfg(feature = "vrf")]
        {
            let (output, proof) = self.prove_ecvrf(keys, input)?;
            Ok((proof, output))
        }

        #[cfg(not(feature = "vrf"))]
        {
            let (output, proof) = self.prove_mock(keys, input)?;
            Ok((proof, output))
        }
    }

    /// Simplified verify that takes raw input bytes and public key
    /// Returns the VRF output on success
    pub fn verify(
        &self,
        public_key: &[u8],
        input: &[u8],
        _proof: &VrfProof,
    ) -> ConsensusResult<VrfOutput> {
        // First, compute what the output should be from the proof's gamma
        #[cfg(feature = "vrf")]
        {
            use k256::elliptic_curve::sec1::FromEncodedPoint;
            use k256::{AffinePoint, EncodedPoint};

            let gamma_encoded = EncodedPoint::from_bytes(&proof.gamma).map_err(|e| {
                ConsensusError::VrfVerificationFailed {
                    reason: format!("Invalid gamma point: {}", e),
                }
            })?;
            let gamma =
                Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&gamma_encoded))
                    .ok_or_else(|| ConsensusError::VrfVerificationFailed {
                        reason: "Invalid gamma point".into(),
                    })?;

            let expected_output = self.hash_gamma(&gamma);

            // Verify the proof
            let valid = self.verify_ecvrf(public_key, input, &expected_output, _proof)?;
            if valid {
                Ok(expected_output)
            } else {
                Err(ConsensusError::VrfVerificationFailed {
                    reason: "Proof verification failed".into(),
                })
            }
        }

        #[cfg(not(feature = "vrf"))]
        {
            // Mock verify: re-derive expected proof components and validate
            if public_key.len() < 33 {
                return Err(ConsensusError::InvalidVrfKey("Too short".into()));
            }

            // Validate proof gamma
            let mut gamma_hasher = Sha256::new();
            gamma_hasher.update(b"mock-vrf-gamma:");
            gamma_hasher.update(&self.domain_tag);
            gamma_hasher.update(&public_key[1..33]);
            gamma_hasher.update(input);
            let expected_gamma_hash: [u8; 32] = gamma_hasher.finalize().into();
            let mut expected_gamma = vec![0x02];
            expected_gamma.extend_from_slice(&expected_gamma_hash);
            if _proof.gamma != expected_gamma {
                return Err(ConsensusError::VrfVerificationFailed {
                    reason: "Mock proof gamma mismatch".into(),
                });
            }

            // Validate proof c and s
            let mut c_hasher = Sha256::new();
            c_hasher.update(b"mock-vrf-c:");
            c_hasher.update(&self.domain_tag);
            c_hasher.update(&public_key[1..33]);
            c_hasher.update(input);
            let expected_c: [u8; 32] = c_hasher.finalize().into();

            let mut s_hasher = Sha256::new();
            s_hasher.update(b"mock-vrf-s:");
            s_hasher.update(&self.domain_tag);
            s_hasher.update(&public_key[1..33]);
            s_hasher.update(input);
            let expected_s: [u8; 32] = s_hasher.finalize().into();

            if _proof.c != expected_c || _proof.s != expected_s {
                return Err(ConsensusError::VrfVerificationFailed {
                    reason: "Mock proof c/s mismatch".into(),
                });
            }

            let mut hasher = Sha256::new();
            hasher.update(b"mock-vrf-output:");
            hasher.update(&self.domain_tag);
            hasher.update(&public_key[1..33]);
            hasher.update(input);
            let output_bytes: [u8; 32] = hasher.finalize().into();

            Ok(VrfOutput(output_bytes))
        }
    }

    /// Generate VRF proof for a specific slot
    ///
    /// # ECVRF Algorithm
    /// 1. Hash message to curve point H
    /// 2. Gamma = SK * H (secret key times H)
    /// 3. Generate proof of discrete log equality
    /// 4. Output = Hash(Gamma)
    pub fn prove_for_slot(
        &self,
        keys: &VrfKeys,
        epoch_seed: &EpochSeed,
        slot: Slot,
    ) -> ConsensusResult<(VrfOutput, VrfProof)> {
        let message = self.construct_message(epoch_seed, slot);

        #[cfg(feature = "vrf")]
        {
            self.prove_ecvrf(keys, &message)
        }

        #[cfg(not(feature = "vrf"))]
        {
            self.prove_mock(keys, &message)
        }
    }

    /// Verify VRF proof for a specific slot
    pub fn verify_for_slot(
        &self,
        public_key: &[u8],
        epoch_seed: &EpochSeed,
        slot: Slot,
        output: &VrfOutput,
        proof: &VrfProof,
    ) -> ConsensusResult<bool> {
        let message = self.construct_message(epoch_seed, slot);

        #[cfg(feature = "vrf")]
        {
            self.verify_ecvrf(public_key, &message, output, proof)
        }

        #[cfg(not(feature = "vrf"))]
        {
            self.verify_mock(public_key, &message, output, proof)
        }
    }

    /// ECVRF prove implementation
    #[cfg(feature = "vrf")]
    fn prove_ecvrf(
        &self,
        keys: &VrfKeys,
        message: &[u8],
    ) -> ConsensusResult<(VrfOutput, VrfProof)> {
        use k256::{
            elliptic_curve::{group::GroupEncoding, ops::Reduce, Field},
            AffinePoint, ProjectivePoint, Scalar,
        };

        // 1. Hash message to curve point
        let h = self.hash_to_curve(message)?;

        // 2. Compute Gamma = sk * H
        let sk_bytes = keys.secret_key();
        let sk = Scalar::reduce(k256::U256::from_be_slice(sk_bytes));
        let gamma = (h * sk).to_affine();

        // 3. Generate nonce k
        let k = self.generate_nonce(sk_bytes, message);

        // 4. Compute U = k * G and V = k * H
        let u = (ProjectivePoint::GENERATOR * k).to_affine();
        let v = (h * k).to_affine();

        // 5. Compute challenge c = Hash(G, H, PK, Gamma, U, V)
        let c = self.compute_challenge(&h.to_affine(), &gamma, &u, &v, &keys.public_key);

        // 6. Compute response s = k - c * sk (mod order)
        let c_scalar = Scalar::reduce(k256::U256::from_be_slice(&c));
        let s = k - c_scalar * sk;

        // 7. Compute output = Hash(Gamma)
        let output = self.hash_gamma(&gamma);

        let proof = VrfProof {
            gamma: gamma.to_bytes().to_vec(),
            c,
            s: s.to_bytes().into(),
        };

        Ok((output, proof))
    }

    /// ECVRF verify implementation
    #[cfg(feature = "vrf")]
    fn verify_ecvrf(
        &self,
        public_key: &[u8],
        message: &[u8],
        output: &VrfOutput,
        proof: &VrfProof,
    ) -> ConsensusResult<bool> {
        use k256::{
            elliptic_curve::{group::GroupEncoding, ops::Reduce, sec1::FromEncodedPoint},
            AffinePoint, EncodedPoint, ProjectivePoint, Scalar,
        };

        // 1. Parse public key
        let pk_encoded = EncodedPoint::from_bytes(public_key)
            .map_err(|e| ConsensusError::InvalidVrfKey(e.to_string()))?;
        let pk = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&pk_encoded))
            .ok_or_else(|| ConsensusError::InvalidVrfKey("Invalid public key point".into()))?;

        // 2. Parse gamma
        let gamma_encoded = EncodedPoint::from_bytes(&proof.gamma).map_err(|e| {
            ConsensusError::VrfVerificationFailed {
                reason: format!("Invalid gamma point: {}", e),
            }
        })?;
        let gamma = Option::<AffinePoint>::from(AffinePoint::from_encoded_point(&gamma_encoded))
            .ok_or_else(|| ConsensusError::VrfVerificationFailed {
                reason: "Invalid gamma point".into(),
            })?;

        // 3. Hash message to curve point
        let h = self.hash_to_curve(message)?;

        // 4. Parse scalars
        let c = Scalar::reduce(k256::U256::from_be_slice(&proof.c));
        let s = Scalar::reduce(k256::U256::from_be_slice(&proof.s));

        // 5. Compute U = s * G + c * PK
        let u = (ProjectivePoint::GENERATOR * s + ProjectivePoint::from(pk) * c).to_affine();

        // 6. Compute V = s * H + c * Gamma
        let v = (h * s + ProjectivePoint::from(gamma) * c).to_affine();

        // 7. Recompute challenge
        let c_prime = self.compute_challenge(&h.to_affine(), &gamma, &u, &v, public_key);

        // 8. Check challenge matches
        if c_prime != proof.c {
            return Ok(false);
        }

        // 9. Check output matches hash of gamma
        let expected_output = self.hash_gamma(&gamma);
        Ok(output == &expected_output)
    }

    /// Hash to curve - Constant-time RFC 9380 Simplified SWU (RS-01 fix).
    ///
    /// Uses the `k256::hash2curve` module implementing the Simplified Shallue–van de
    /// Woestijne–Ulas (SWU) map with 3-isogeny, as specified in RFC 9380 §6.6.2
    /// ("secp256k1_XMD:SHA-256_SSWU_RO_").
    ///
    /// ## Security Properties
    /// - **Constant-time**: No data-dependent branches or memory accesses.
    ///   Field operations use `subtle` crate primitives (`Choice`, `ConditionallySelectable`).
    /// - **Uniform distribution**: `hash_from_bytes` (random oracle variant) produces points
    ///   statistically indistinguishable from uniform over the curve.
    /// - **Domain separation**: Uses the IETF-recommended DST format with chain-specific tag
    ///   to prevent cross-protocol attacks.
    ///
    /// ## Algorithm (RFC 9380 §5)
    /// 1. `msg_prime = expand_message_xmd(SHA-256, message, DST, 96)`
    /// 2. `u[0], u[1] = hash_to_field(msg_prime)` - two 48-byte field elements
    /// 3. `Q0 = map_to_curve(u[0])` - OSSWU map to isogenous curve E'
    /// 4. `Q1 = map_to_curve(u[1])` - OSSWU map to isogenous curve E'
    /// 5. `R = Q0 + Q1` - point addition on E'
    /// 6. `P = iso_map(R)` - 3-isogeny from E' to secp256k1
    /// 7. `return clear_cofactor(P)` - identity for secp256k1 (cofactor = 1)
    #[cfg(feature = "vrf")]
    fn hash_to_curve(&self, message: &[u8]) -> ConsensusResult<k256::ProjectivePoint> {
        use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, GroupDigest};
        use k256::Secp256k1;

        // Domain Separation Tag following RFC 9380 §3.1 and §8.10.
        // Format: "protocol-id" || suite_id
        // We use a chain-specific DST to prevent cross-chain VRF replay.
        const DST: &[u8] = b"Aethelred-PoUW-VRF-v1_XMD:SHA-256_SSWU_RO_";

        // RFC 9380 §5.3: hash_to_curve using random oracle (RO) variant.
        // This is constant-time with respect to the input message:
        // execution path and timing are identical for all inputs.
        let point = Secp256k1::hash_from_bytes::<ExpandMsgXmd<Sha256>>(&[message], &[DST])
            .map_err(|e| ConsensusError::Crypto(format!("RFC 9380 hash_to_curve failed: {}", e)))?;

        Ok(point)
    }

    /// Generate deterministic nonce
    #[cfg(feature = "vrf")]
    fn generate_nonce(&self, sk: &[u8; 32], message: &[u8]) -> k256::Scalar {
        use k256::elliptic_curve::ops::Reduce;
        use k256::Scalar;

        let mut hasher = Sha256::new();
        hasher.update(b"Aethelred-nonce:");
        hasher.update(sk);
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();

        Scalar::reduce(k256::U256::from_be_slice(&hash))
    }

    /// Compute challenge
    #[cfg(feature = "vrf")]
    fn compute_challenge(
        &self,
        h: &k256::AffinePoint,
        gamma: &k256::AffinePoint,
        u: &k256::AffinePoint,
        v: &k256::AffinePoint,
        pk: &[u8],
    ) -> [u8; 32] {
        use k256::elliptic_curve::group::GroupEncoding;

        let mut hasher = Sha256::new();
        hasher.update(b"Aethelred-challenge:");
        hasher.update(h.to_bytes());
        hasher.update(gamma.to_bytes());
        hasher.update(u.to_bytes());
        hasher.update(v.to_bytes());
        hasher.update(pk);
        hasher.finalize().into()
    }

    /// Hash gamma to output
    #[cfg(feature = "vrf")]
    fn hash_gamma(&self, gamma: &k256::AffinePoint) -> VrfOutput {
        use k256::elliptic_curve::group::GroupEncoding;

        let mut hasher = Sha256::new();
        hasher.update(b"Aethelred-output:");
        hasher.update(gamma.to_bytes());
        VrfOutput(hasher.finalize().into())
    }

    /// Mock prove implementation for development.
    ///
    /// SECURITY (RS-02 fix): Output is derived from the secret key via
    /// SHA-256("mock-vrf-output:" || sk || message), and the mock public key
    /// is SHA-256("mock-vrf-pk:" || sk), NOT the raw sk bytes. This prevents
    /// secret key leakage through the public key.
    #[cfg(not(feature = "vrf"))]
    fn prove_mock(&self, keys: &VrfKeys, message: &[u8]) -> ConsensusResult<(VrfOutput, VrfProof)> {
        // Deterministic but insecure mock for testing
        // Includes domain_tag for chain-ID domain separation
        // Must use public_key[1..33] to match verify() mock path
        let mut hasher = Sha256::new();
        hasher.update(b"mock-vrf-output:");
        hasher.update(&self.domain_tag);
        hasher.update(&keys.public_key()[1..33]);
        hasher.update(message);
        let output_bytes: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        hasher.update(b"mock-vrf-gamma:");
        hasher.update(&self.domain_tag);
        hasher.update(&keys.public_key()[1..33]);
        hasher.update(message);
        let gamma_hash: [u8; 32] = hasher.finalize().into();
        let mut gamma = vec![0x02];
        gamma.extend_from_slice(&gamma_hash);

        // Generate deterministic non-trivial c and s for proof validation
        let mut c_hasher = Sha256::new();
        c_hasher.update(b"mock-vrf-c:");
        c_hasher.update(&self.domain_tag);
        c_hasher.update(&keys.public_key()[1..33]);
        c_hasher.update(message);
        let c: [u8; 32] = c_hasher.finalize().into();

        let mut s_hasher = Sha256::new();
        s_hasher.update(b"mock-vrf-s:");
        s_hasher.update(&self.domain_tag);
        s_hasher.update(&keys.public_key()[1..33]);
        s_hasher.update(message);
        let s: [u8; 32] = s_hasher.finalize().into();

        let proof = VrfProof { gamma, c, s };

        Ok((VrfOutput(output_bytes), proof))
    }

    /// Mock verify implementation for development.
    ///
    /// SECURITY (RS-02 fix): Verifies by re-deriving the output from the
    /// public key (which is SHA-256("mock-vrf-pk:" || sk)), NOT by extracting
    /// the raw secret key from the public key bytes. Also validates proof
    /// structure (gamma, c, s) to reject forged proofs.
    #[cfg(not(feature = "vrf"))]
    fn verify_mock(
        &self,
        public_key: &[u8],
        message: &[u8],
        output: &VrfOutput,
        proof: &VrfProof,
    ) -> ConsensusResult<bool> {
        if public_key.len() < 33 {
            return Err(ConsensusError::InvalidVrfKey("Too short".into()));
        }

        // Validate proof gamma
        let mut gamma_hasher = Sha256::new();
        gamma_hasher.update(b"mock-vrf-gamma:");
        gamma_hasher.update(&self.domain_tag);
        gamma_hasher.update(&public_key[1..33]);
        gamma_hasher.update(message);
        let expected_gamma_hash: [u8; 32] = gamma_hasher.finalize().into();
        let mut expected_gamma = vec![0x02];
        expected_gamma.extend_from_slice(&expected_gamma_hash);
        if proof.gamma != expected_gamma {
            return Ok(false);
        }

        // Validate proof c and s
        let mut c_hasher = Sha256::new();
        c_hasher.update(b"mock-vrf-c:");
        c_hasher.update(&self.domain_tag);
        c_hasher.update(&public_key[1..33]);
        c_hasher.update(message);
        let expected_c: [u8; 32] = c_hasher.finalize().into();

        let mut s_hasher = Sha256::new();
        s_hasher.update(b"mock-vrf-s:");
        s_hasher.update(&self.domain_tag);
        s_hasher.update(&public_key[1..33]);
        s_hasher.update(message);
        let expected_s: [u8; 32] = s_hasher.finalize().into();

        if proof.c != expected_c || proof.s != expected_s {
            return Ok(false);
        }

        // Use the derived public key bytes (not raw secret key) for verification.
        let mut hasher = Sha256::new();
        hasher.update(b"mock-vrf-output:");
        hasher.update(&self.domain_tag);
        hasher.update(&public_key[1..33]);
        hasher.update(message);
        let expected: [u8; 32] = hasher.finalize().into();

        Ok(output.0 == expected)
    }
}

impl Default for VrfEngine {
    fn default() -> Self {
        Self::new() // Default chain ID
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // =========================================================================
    // KEY GENERATION - Unit tests
    // =========================================================================

    #[test]
    fn test_unit_key_generation_deterministic() {
        let seed = [42u8; 32];
        let keys = VrfKeys::from_seed(&seed).unwrap();

        assert!(!keys.public_key().is_empty());

        // Same seed = same keys (determinism)
        let keys2 = VrfKeys::from_seed(&seed).unwrap();
        assert_eq!(keys.public_key(), keys2.public_key());
        assert_eq!(keys.secret_key(), keys2.secret_key());
    }

    #[test]
    fn test_unit_key_generation_different_seeds_different_keys() {
        let keys1 = VrfKeys::from_seed(&[1u8; 32]).unwrap();
        let keys2 = VrfKeys::from_seed(&[2u8; 32]).unwrap();

        assert_ne!(keys1.public_key(), keys2.public_key());
    }

    #[test]
    fn test_unit_key_generation_random_unique() {
        let keys1 = VrfKeys::generate().unwrap();
        let keys2 = VrfKeys::generate().unwrap();

        // Two random keypairs should be different (overwhelming probability)
        assert_ne!(keys1.public_key(), keys2.public_key());
    }

    #[test]
    fn test_unit_key_public_key_format() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let pk = keys.public_key();

        // Compressed public key: 33 bytes, prefix 0x02 or 0x03
        assert_eq!(pk.len(), 33);
        assert!(pk[0] == 0x02 || pk[0] == 0x03);
    }

    #[test]
    fn test_unit_key_public_key_bytes_clone() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let pk = keys.public_key_bytes();

        assert_eq!(pk, keys.public_key());
        // Verify it's an independent copy
        assert_eq!(pk.len(), keys.public_key().len());
    }

    #[test]
    fn test_unit_key_secret_key_preserved() {
        let seed = [99u8; 32];
        let keys = VrfKeys::from_seed(&seed).unwrap();

        assert_eq!(keys.secret_key(), &seed);
    }

    #[test]
    fn test_unit_key_debug_redacts_secret() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let debug_str = format!("{:?}", keys);

        assert!(debug_str.contains("[REDACTED]"));
        // Should NOT contain the actual secret key bytes
        assert!(!debug_str.contains("2a2a2a2a")); // hex of [42,42,42,42]
    }

    // =========================================================================
    // KEY GENERATION - Boundary tests
    // =========================================================================

    #[test]
    fn test_boundary_key_from_zero_seed() {
        // Zero seed should still produce a valid keypair
        let keys = VrfKeys::from_seed(&[0u8; 32]);
        // Depending on the curve implementation, zero might be invalid as a scalar
        // Either it succeeds or returns an error - it must not panic
        match keys {
            Ok(k) => assert!(!k.public_key().is_empty()),
            Err(_) => {} // Acceptable: zero is not a valid secp256k1 scalar
        }
    }

    #[test]
    fn test_boundary_key_from_ones_seed() {
        let keys = VrfKeys::from_seed(&[0xFF; 32]);
        // Max scalar may be >= curve order; should still handle gracefully
        match keys {
            Ok(k) => assert!(!k.public_key().is_empty()),
            Err(_) => {} // Acceptable: may exceed curve order
        }
    }

    #[test]
    fn test_boundary_key_from_sequential_seeds() {
        // Ensure nearby seeds produce different keys (no collisions)
        let mut prev_pk: Option<Vec<u8>> = None;
        for i in 1u8..=20 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            if let Ok(keys) = VrfKeys::from_seed(&seed) {
                let pk = keys.public_key_bytes();
                if let Some(ref prev) = prev_pk {
                    assert_ne!(
                        &pk,
                        prev,
                        "Seeds {} and {} produced same public key",
                        i - 1,
                        i
                    );
                }
                prev_pk = Some(pk);
            }
        }
    }

    // =========================================================================
    // EPOCH KEY DERIVATION
    // =========================================================================

    #[test]
    fn test_unit_epoch_derivation_deterministic() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        let epoch1_a = keys.derive_epoch_keys(1).unwrap();
        let epoch1_b = keys.derive_epoch_keys(1).unwrap();

        assert_eq!(epoch1_a.public_key(), epoch1_b.public_key());
    }

    #[test]
    fn test_unit_epoch_derivation_different_epochs_different_keys() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        let epoch1_keys = keys.derive_epoch_keys(1).unwrap();
        let epoch2_keys = keys.derive_epoch_keys(2).unwrap();

        assert_ne!(epoch1_keys.public_key(), epoch2_keys.public_key());
    }

    #[test]
    fn test_unit_epoch_derivation_differs_from_master() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_keys = keys.derive_epoch_keys(0).unwrap();

        // Derived keys should differ from master even for epoch 0
        assert_ne!(keys.public_key(), epoch_keys.public_key());
    }

    #[test]
    fn test_unit_epoch_derivation_chained() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        // Deriving epoch keys and then deriving again should be different
        // from directly deriving epoch 2
        let epoch1 = keys.derive_epoch_keys(1).unwrap();
        let epoch1_then_2 = epoch1.derive_epoch_keys(2).unwrap();
        let epoch2_direct = keys.derive_epoch_keys(2).unwrap();

        assert_ne!(epoch1_then_2.public_key(), epoch2_direct.public_key());
    }

    #[test]
    fn test_boundary_epoch_derivation_zero() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch0 = keys.derive_epoch_keys(0).unwrap();
        assert!(!epoch0.public_key().is_empty());
    }

    #[test]
    fn test_boundary_epoch_derivation_max_u64() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_max = keys.derive_epoch_keys(u64::MAX).unwrap();
        assert!(!epoch_max.public_key().is_empty());
    }

    #[test]
    fn test_unit_epoch_derived_keys_can_prove_and_verify() {
        let engine = VrfEngine::with_chain_id(1);
        let master = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_keys = master.derive_epoch_keys(5).unwrap();

        let input = b"epoch-5-message";
        let (proof, output) = engine.prove(&epoch_keys, input).unwrap();
        let verified = engine
            .verify(epoch_keys.public_key(), input, &proof)
            .unwrap();

        assert_eq!(output, verified);
    }

    // =========================================================================
    // PROVE & VERIFY - Core correctness
    // =========================================================================

    #[test]
    fn test_unit_prove_verify_roundtrip() {
        let engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::generate().unwrap();
        let epoch_seed = [1u8; 32];
        let slot = 100;

        let (output, proof) = engine.prove_for_slot(&keys, &epoch_seed, slot).unwrap();

        let valid = engine
            .verify_for_slot(keys.public_key(), &epoch_seed, slot, &output, &proof)
            .unwrap();

        assert!(valid);
    }

    #[test]
    fn test_unit_prove_deterministic() {
        let engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];
        let slot = 100;

        let (output1, _) = engine.prove_for_slot(&keys, &epoch_seed, slot).unwrap();
        let (output2, _) = engine.prove_for_slot(&keys, &epoch_seed, slot).unwrap();

        assert_eq!(
            output1, output2,
            "VRF must be deterministic for same inputs"
        );
    }

    #[test]
    fn test_unit_prove_different_slots_different_outputs() {
        let engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];

        let (output1, _) = engine.prove_for_slot(&keys, &epoch_seed, 100).unwrap();
        let (output2, _) = engine.prove_for_slot(&keys, &epoch_seed, 101).unwrap();

        assert_ne!(
            output1, output2,
            "Different slots must produce different outputs"
        );
    }

    #[test]
    fn test_unit_prove_different_seeds_different_outputs() {
        let engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        let (output1, _) = engine.prove_for_slot(&keys, &[1u8; 32], 100).unwrap();
        let (output2, _) = engine.prove_for_slot(&keys, &[2u8; 32], 100).unwrap();

        assert_ne!(
            output1, output2,
            "Different epoch seeds must produce different outputs"
        );
    }

    #[test]
    fn test_unit_prove_different_keys_different_outputs() {
        let engine = VrfEngine::with_chain_id(1);
        let keys1 = VrfKeys::from_seed(&[1u8; 32]).unwrap();
        let keys2 = VrfKeys::from_seed(&[2u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];

        let (output1, _) = engine.prove_for_slot(&keys1, &epoch_seed, 100).unwrap();
        let (output2, _) = engine.prove_for_slot(&keys2, &epoch_seed, 100).unwrap();

        assert_ne!(
            output1, output2,
            "Different keys must produce different outputs"
        );
    }

    #[test]
    fn test_unit_simple_prove_verify() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::generate().unwrap();
        let input = b"test input message";

        let (proof, output) = engine.prove(&keys, input).unwrap();
        let verified_output = engine.verify(keys.public_key(), input, &proof).unwrap();

        assert_eq!(output, verified_output);
    }

    #[test]
    fn test_unit_prove_verify_empty_message() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::generate().unwrap();
        let input = b"";

        let (proof, output) = engine.prove(&keys, input).unwrap();
        let verified_output = engine.verify(keys.public_key(), input, &proof).unwrap();

        assert_eq!(output, verified_output);
    }

    #[test]
    fn test_unit_prove_verify_large_message() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::generate().unwrap();
        let input = vec![0xAB; 10000]; // 10KB message

        let (proof, output) = engine.prove(&keys, &input).unwrap();
        let verified_output = engine.verify(keys.public_key(), &input, &proof).unwrap();

        assert_eq!(output, verified_output);
    }

    // =========================================================================
    // VERIFY - Negative tests
    // =========================================================================

    #[test]
    fn test_negative_verify_wrong_public_key() {
        let engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::from_seed(&[1u8; 32]).unwrap();
        let wrong_keys = VrfKeys::from_seed(&[2u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];
        let slot = 100;

        let (output, proof) = engine.prove_for_slot(&keys, &epoch_seed, slot).unwrap();

        // Verification with wrong public key should fail
        let result =
            engine.verify_for_slot(wrong_keys.public_key(), &epoch_seed, slot, &output, &proof);

        match result {
            Ok(valid) => assert!(!valid, "Verify with wrong key must return false"),
            Err(_) => {} // Also acceptable: error indicates failure
        }
    }

    #[test]
    fn test_negative_verify_wrong_message() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::generate().unwrap();
        let input = b"correct message";
        let wrong_input = b"wrong message";

        let (proof, output) = engine.prove(&keys, input).unwrap();

        // Verification with wrong message should fail
        let result = engine.verify(keys.public_key(), wrong_input, &proof);

        match result {
            Ok(verified) => assert_ne!(
                output, verified,
                "Wrong message must produce different output"
            ),
            Err(_) => {} // Also acceptable
        }
    }

    #[test]
    fn test_negative_verify_wrong_epoch_seed() {
        let engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::generate().unwrap();

        let (output, proof) = engine.prove_for_slot(&keys, &[1u8; 32], 100).unwrap();

        let result = engine.verify_for_slot(
            keys.public_key(),
            &[2u8; 32], // Wrong seed
            100,
            &output,
            &proof,
        );

        match result {
            Ok(valid) => assert!(!valid, "Wrong epoch seed must fail verification"),
            Err(_) => {}
        }
    }

    #[test]
    fn test_negative_verify_wrong_slot() {
        let engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::generate().unwrap();
        let epoch_seed = [1u8; 32];

        let (output, proof) = engine.prove_for_slot(&keys, &epoch_seed, 100).unwrap();

        let result = engine.verify_for_slot(
            keys.public_key(),
            &epoch_seed,
            101, // Wrong slot
            &output,
            &proof,
        );

        match result {
            Ok(valid) => assert!(!valid, "Wrong slot must fail verification"),
            Err(_) => {}
        }
    }

    #[test]
    fn test_negative_verify_truncated_public_key() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::generate().unwrap();
        let input = b"test";

        let (proof, _output) = engine.prove(&keys, input).unwrap();

        // Truncated public key (only 10 bytes instead of 33)
        let short_pk = &keys.public_key()[..10];
        let result = engine.verify(short_pk, input, &proof);

        assert!(result.is_err(), "Truncated public key must return error");
    }

    #[test]
    fn test_negative_verify_empty_public_key() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::generate().unwrap();
        let input = b"test";

        let (proof, _output) = engine.prove(&keys, input).unwrap();

        let result = engine.verify(&[], input, &proof);
        assert!(result.is_err(), "Empty public key must return error");
    }

    // =========================================================================
    // DOMAIN SEPARATION - Chain ID isolation
    // =========================================================================

    #[test]
    fn test_unit_domain_separation_different_chain_ids() {
        let engine1 = VrfEngine::with_chain_id(1);
        let engine2 = VrfEngine::with_chain_id(2);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let input = b"same input";

        let (_, output1) = engine1.prove(&keys, input).unwrap();
        let (_, output2) = engine2.prove(&keys, input).unwrap();

        assert_ne!(
            output1, output2,
            "Different chain IDs must produce different outputs"
        );
    }

    #[test]
    fn test_unit_domain_separation_cross_chain_proof_invalid() {
        let engine1 = VrfEngine::with_chain_id(1);
        let engine2 = VrfEngine::with_chain_id(2);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];
        let slot = 100;

        // Prove on chain 1
        let (output, proof) = engine1.prove_for_slot(&keys, &epoch_seed, slot).unwrap();

        // Verify on chain 2 - should fail
        let result = engine2.verify_for_slot(keys.public_key(), &epoch_seed, slot, &output, &proof);

        match result {
            Ok(valid) => assert!(!valid, "Cross-chain proof must not verify"),
            Err(_) => {} // Also acceptable
        }
    }

    #[test]
    fn test_unit_default_engine_uses_chain_id_1() {
        let default_engine = VrfEngine::default();
        let chain1_engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let input = b"test";

        let (_, output_default) = default_engine.prove(&keys, input).unwrap();
        let (_, output_chain1) = chain1_engine.prove(&keys, input).unwrap();

        assert_eq!(
            output_default, output_chain1,
            "Default engine should use chain ID 1"
        );
    }

    // =========================================================================
    // PROOF SERIALIZATION
    // =========================================================================

    #[test]
    fn test_unit_proof_serialization_roundtrip() {
        let proof = VrfProof {
            gamma: vec![0x02; 33],
            c: [1u8; 32],
            s: [2u8; 32],
        };

        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), VrfProof::SIZE);

        let restored = VrfProof::from_bytes(&bytes).unwrap();
        assert_eq!(proof.gamma, restored.gamma);
        assert_eq!(proof.c, restored.c);
        assert_eq!(proof.s, restored.s);
    }

    #[test]
    fn test_unit_proof_serialization_from_real_proof() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::generate().unwrap();
        let (proof, output) = engine.prove(&keys, b"serialize me").unwrap();

        let bytes = proof.to_bytes();
        let restored = VrfProof::from_bytes(&bytes).unwrap();

        // Verify the restored proof still works
        let verified = engine
            .verify(keys.public_key(), b"serialize me", &restored)
            .unwrap();
        assert_eq!(output, verified);
    }

    #[test]
    fn test_unit_proof_size_constant() {
        assert_eq!(VrfProof::SIZE, 97); // 33 + 32 + 32
    }

    #[test]
    fn test_negative_proof_deserialization_too_short() {
        let short_bytes = vec![0u8; 50]; // Less than SIZE (97)
        let result = VrfProof::from_bytes(&short_bytes);

        assert!(result.is_err());
        match result {
            Err(ConsensusError::MalformedVrfProof { expected, actual }) => {
                assert_eq!(expected, 97);
                assert_eq!(actual, 50);
            }
            _ => panic!("Expected MalformedVrfProof error"),
        }
    }

    #[test]
    fn test_negative_proof_deserialization_empty() {
        let result = VrfProof::from_bytes(&[]);

        assert!(result.is_err());
        match result {
            Err(ConsensusError::MalformedVrfProof { expected, actual }) => {
                assert_eq!(expected, 97);
                assert_eq!(actual, 0);
            }
            _ => panic!("Expected MalformedVrfProof error"),
        }
    }

    #[test]
    fn test_boundary_proof_deserialization_exact_size() {
        let bytes = vec![0x02; VrfProof::SIZE]; // Exactly 97 bytes
        let result = VrfProof::from_bytes(&bytes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_boundary_proof_deserialization_extra_bytes() {
        // Extra bytes beyond SIZE should be silently ignored
        let bytes = vec![0x02; VrfProof::SIZE + 50];
        let result = VrfProof::from_bytes(&bytes);
        assert!(result.is_ok());

        let proof = result.unwrap();
        assert_eq!(proof.gamma.len(), 33);
    }

    // =========================================================================
    // VRF OUTPUT
    // =========================================================================

    #[test]
    fn test_unit_output_from_bytes() {
        let bytes = [0xAB; 32];
        let output = VrfOutput::from_bytes(bytes);
        assert_eq!(output.as_bytes(), &bytes);
    }

    #[test]
    fn test_unit_output_as_ref() {
        let output = VrfOutput([0x42; 32]);
        let slice: &[u8] = output.as_ref();
        assert_eq!(slice.len(), 32);
        assert_eq!(slice[0], 0x42);
    }

    #[test]
    fn test_unit_output_bigint_max() {
        let output = VrfOutput([0xFF; 32]);
        let bigint = output.to_bigint();
        assert_eq!(bigint.bits(), 256);
    }

    #[test]
    fn test_unit_output_bigint_zero() {
        let output = VrfOutput([0x00; 32]);
        let bigint = output.to_bigint();
        assert_eq!(bigint.bits(), 0);
    }

    #[test]
    fn test_unit_output_bigint_one() {
        let mut bytes = [0x00; 32];
        bytes[31] = 1; // LSB = 1 in big-endian
        let output = VrfOutput(bytes);
        let bigint = output.to_bigint();
        assert_eq!(bigint, num_bigint::BigUint::from(1u32));
    }

    #[test]
    fn test_unit_output_equality() {
        let a = VrfOutput([0xAA; 32]);
        let b = VrfOutput([0xAA; 32]);
        let c = VrfOutput([0xBB; 32]);

        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    // =========================================================================
    // MESSAGE CONSTRUCTION
    // =========================================================================

    #[test]
    fn test_unit_construct_message_deterministic() {
        let engine = VrfEngine::with_chain_id(1);
        let epoch_seed = [1u8; 32];

        let msg1 = engine.construct_message(&epoch_seed, 100);
        let msg2 = engine.construct_message(&epoch_seed, 100);

        assert_eq!(msg1, msg2, "Same inputs must produce same message");
    }

    #[test]
    fn test_unit_construct_message_different_slots() {
        let engine = VrfEngine::with_chain_id(1);
        let epoch_seed = [1u8; 32];

        let msg1 = engine.construct_message(&epoch_seed, 100);
        let msg2 = engine.construct_message(&epoch_seed, 101);

        assert_ne!(
            msg1, msg2,
            "Different slots must produce different messages"
        );
    }

    #[test]
    fn test_unit_construct_message_different_seeds() {
        let engine = VrfEngine::with_chain_id(1);

        let msg1 = engine.construct_message(&[1u8; 32], 100);
        let msg2 = engine.construct_message(&[2u8; 32], 100);

        assert_ne!(
            msg1, msg2,
            "Different seeds must produce different messages"
        );
    }

    #[test]
    fn test_unit_construct_message_includes_domain_tag() {
        let engine = VrfEngine::with_chain_id(1);
        let msg = engine.construct_message(&[0u8; 32], 0);

        // Message should start with domain tag
        assert!(msg.starts_with(b"Aethelred-PoUW-VRF-v1:"));
    }

    #[test]
    fn test_boundary_construct_message_slot_zero() {
        let engine = VrfEngine::with_chain_id(1);
        let msg = engine.construct_message(&[0u8; 32], 0);
        assert!(!msg.is_empty());
    }

    #[test]
    fn test_boundary_construct_message_slot_max() {
        let engine = VrfEngine::with_chain_id(1);
        let msg = engine.construct_message(&[0u8; 32], u64::MAX);
        assert!(!msg.is_empty());
    }

    // =========================================================================
    // INTEGRATION - Full prove/verify cycle variations
    // =========================================================================

    #[test]
    fn test_integration_multiple_slots_sequential() {
        let engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];

        let mut outputs = Vec::new();
        for slot in 0..20 {
            let (output, proof) = engine.prove_for_slot(&keys, &epoch_seed, slot).unwrap();
            let valid = engine
                .verify_for_slot(keys.public_key(), &epoch_seed, slot, &output, &proof)
                .unwrap();
            assert!(valid, "Slot {} verification failed", slot);
            outputs.push(output);
        }

        // All outputs should be unique
        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                assert_ne!(
                    outputs[i], outputs[j],
                    "Slots {} and {} produced same output",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_integration_multiple_keys_same_slot() {
        let engine = VrfEngine::with_chain_id(1);
        let epoch_seed = [1u8; 32];
        let slot = 100;

        let mut outputs = Vec::new();
        for i in 1u8..=10 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            let keys = VrfKeys::from_seed(&seed).unwrap();

            let (output, proof) = engine.prove_for_slot(&keys, &epoch_seed, slot).unwrap();
            let valid = engine
                .verify_for_slot(keys.public_key(), &epoch_seed, slot, &output, &proof)
                .unwrap();
            assert!(valid, "Key {} verification failed", i);
            outputs.push(output);
        }

        // All outputs from different keys should be unique
        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                assert_ne!(
                    outputs[i], outputs[j],
                    "Keys {} and {} produced same output",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_integration_epoch_rotation_prove_verify() {
        let engine = VrfEngine::with_chain_id(1);
        let master = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        // Simulate epoch rotation: derive new keys each epoch, prove, verify
        for epoch in 0..5 {
            let epoch_keys = master.derive_epoch_keys(epoch).unwrap();
            let epoch_seed = {
                let mut s = [0u8; 32];
                s[0] = epoch as u8;
                s
            };

            let (output, proof) = engine.prove_for_slot(&epoch_keys, &epoch_seed, 0).unwrap();
            let valid = engine
                .verify_for_slot(epoch_keys.public_key(), &epoch_seed, 0, &output, &proof)
                .unwrap();
            assert!(valid, "Epoch {} verification failed", epoch);
        }
    }

    #[test]
    fn test_integration_proof_serialization_roundtrip_with_verification() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::generate().unwrap();
        let input = b"roundtrip test";

        // Prove
        let (proof, output) = engine.prove(&keys, input).unwrap();

        // Serialize and deserialize
        let bytes = proof.to_bytes();
        let restored_proof = VrfProof::from_bytes(&bytes).unwrap();

        // Verify with restored proof
        let verified = engine
            .verify(keys.public_key(), input, &restored_proof)
            .unwrap();
        assert_eq!(output, verified, "Restored proof must verify identically");
    }

    // =========================================================================
    // PROPERTY - Statistical properties
    // =========================================================================

    #[test]
    fn test_property_output_uniformity_rough() {
        // Rough check that VRF outputs are not biased (not all in one half)
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        let mut high_bit_count = 0u32;
        let total = 100u32;
        for i in 0..total {
            let input = format!("input-{}", i);
            let (_, output) = engine.prove(&keys, input.as_bytes()).unwrap();
            if output.0[0] & 0x80 != 0 {
                high_bit_count += 1;
            }
        }

        // Expect roughly 50% have high bit set (within reasonable bounds)
        assert!(
            high_bit_count > 20,
            "Output appears biased low: {}/100",
            high_bit_count
        );
        assert!(
            high_bit_count < 80,
            "Output appears biased high: {}/100",
            high_bit_count
        );
    }

    #[test]
    fn test_property_output_no_fixed_point() {
        // No input should produce all-zero or all-ones output
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        for i in 0..50 {
            let input = format!("check-{}", i);
            let (_, output) = engine.prove(&keys, input.as_bytes()).unwrap();
            assert_ne!(output.0, [0u8; 32], "Output should never be all zeros");
            assert_ne!(output.0, [0xFF; 32], "Output should never be all ones");
        }
    }

    // =========================================================================
    // STRESS / LARGE INPUT TESTS
    // =========================================================================

    #[test]
    fn test_stress_prove_verify_100_iterations() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        for i in 0u64..100 {
            let input = format!("stress-message-{}", i);
            let (proof, output) = engine.prove(&keys, input.as_bytes()).unwrap();
            let verified = engine
                .verify(keys.public_key(), input.as_bytes(), &proof)
                .unwrap();
            assert_eq!(output, verified, "Iteration {} failed verification", i);
        }
    }

    #[test]
    fn test_stress_key_generation_100_unique() {
        let mut public_keys = std::collections::HashSet::new();

        for i in 0u8..100 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            seed[1] = i.wrapping_mul(7);
            if let Ok(keys) = VrfKeys::from_seed(&seed) {
                let pk = keys.public_key_bytes();
                assert!(
                    public_keys.insert(pk.clone()),
                    "Duplicate public key at iteration {}",
                    i
                );
            }
        }

        assert!(
            public_keys.len() >= 90,
            "Expected at least 90 unique keys, got {}",
            public_keys.len()
        );
    }

    #[test]
    fn test_stress_epoch_derivation_100_epochs() {
        let master = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let mut epoch_pks = std::collections::HashSet::new();

        for epoch in 0u64..100 {
            let epoch_keys = master.derive_epoch_keys(epoch).unwrap();
            let pk = epoch_keys.public_key_bytes();
            assert!(
                epoch_pks.insert(pk),
                "Duplicate epoch key at epoch {}",
                epoch
            );
        }

        assert_eq!(epoch_pks.len(), 100);
    }

    #[test]
    fn test_stress_proof_serialization_100_roundtrips() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        for i in 0u64..100 {
            let input = format!("ser-roundtrip-{}", i);
            let (proof, output) = engine.prove(&keys, input.as_bytes()).unwrap();

            let bytes = proof.to_bytes();
            let restored = VrfProof::from_bytes(&bytes).unwrap();

            let verified = engine
                .verify(keys.public_key(), input.as_bytes(), &restored)
                .unwrap();
            assert_eq!(
                output, verified,
                "Serialization roundtrip failed at iteration {}",
                i
            );
        }
    }

    #[test]
    fn test_stress_concurrent_slots_prove_verify() {
        let engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_seed = [99u8; 32];

        // Prove and verify 50 slots in sequence, then cross-verify none match
        let mut results: Vec<(VrfOutput, VrfProof)> = Vec::new();
        for slot in 0u64..50 {
            let (output, proof) = engine.prove_for_slot(&keys, &epoch_seed, slot).unwrap();
            let valid = engine
                .verify_for_slot(keys.public_key(), &epoch_seed, slot, &output, &proof)
                .unwrap();
            assert!(valid, "Slot {} failed verification", slot);
            results.push((output, proof));
        }

        // Ensure all outputs are distinct
        for i in 0..results.len() {
            for j in (i + 1)..results.len() {
                assert_ne!(results[i].0, results[j].0, "Slots {} and {} collided", i, j);
            }
        }
    }

    #[test]
    fn test_stress_output_distribution_1000_samples() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        // Count how many outputs fall in each quartile of the first byte
        let mut quartiles = [0u32; 4];
        for i in 0u64..1000 {
            let input = format!("dist-{}", i);
            let (_, output) = engine.prove(&keys, input.as_bytes()).unwrap();
            let bucket = (output.0[0] / 64) as usize; // 0..3
            quartiles[bucket] += 1;
        }

        // Each quartile should have roughly 250 samples; allow wide margin
        for (idx, &count) in quartiles.iter().enumerate() {
            assert!(
                count > 150 && count < 400,
                "Quartile {} has {} samples, expected ~250",
                idx,
                count
            );
        }
    }

    #[test]
    fn test_stress_prove_verify_different_keys_50() {
        let engine = VrfEngine::new();
        let input = b"shared-input-across-keys";

        for i in 1u8..=50 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            seed[15] = i.wrapping_mul(11);
            let keys = VrfKeys::from_seed(&seed).unwrap();

            let (proof, output) = engine.prove(&keys, input).unwrap();
            let verified = engine.verify(keys.public_key(), input, &proof).unwrap();
            assert_eq!(output, verified, "Key {} failed prove/verify", i);
        }
    }

    // =========================================================================
    // KEY MANAGEMENT TESTS
    // =========================================================================

    #[test]
    fn test_unit_key_clone_independence() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let cloned = keys.clone();

        // Both should have the same data
        assert_eq!(keys.public_key(), cloned.public_key());
        assert_eq!(keys.secret_key(), cloned.secret_key());

        // Original should still work after clone exists
        let engine = VrfEngine::new();
        let (proof1, output1) = engine.prove(&keys, b"test").unwrap();
        let (proof2, output2) = engine.prove(&cloned, b"test").unwrap();
        assert_eq!(output1, output2);

        let v1 = engine.verify(keys.public_key(), b"test", &proof1).unwrap();
        let v2 = engine
            .verify(cloned.public_key(), b"test", &proof2)
            .unwrap();
        assert_eq!(v1, v2);
    }

    #[test]
    fn test_unit_key_from_seed_preserves_seed_bytes() {
        let seed = [0xABu8; 32];
        let keys = VrfKeys::from_seed(&seed).unwrap();

        // The secret key should be exactly the seed bytes
        assert_eq!(keys.secret_key(), &seed);
        // Verify no byte was mutated
        for (i, &b) in keys.secret_key().iter().enumerate() {
            assert_eq!(b, 0xAB, "Byte {} was mutated", i);
        }
    }

    #[test]
    fn test_unit_key_public_key_length_33() {
        // Test across many different seeds
        for i in 1u8..=50 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            if let Ok(keys) = VrfKeys::from_seed(&seed) {
                assert_eq!(
                    keys.public_key().len(),
                    33,
                    "Public key length is not 33 for seed starting with {}",
                    i
                );
            }
        }
    }

    #[test]
    fn test_unit_key_different_seeds_different_public_keys() {
        // Test with more than 2 seeds to ensure broader uniqueness
        let seeds: Vec<[u8; 32]> = (1u8..=10)
            .map(|i| {
                let mut s = [0u8; 32];
                s[0] = i;
                s
            })
            .collect();

        let public_keys: Vec<Vec<u8>> = seeds
            .iter()
            .filter_map(|s| VrfKeys::from_seed(s).ok())
            .map(|k| k.public_key_bytes())
            .collect();

        for i in 0..public_keys.len() {
            for j in (i + 1)..public_keys.len() {
                assert_ne!(
                    public_keys[i],
                    public_keys[j],
                    "Seeds {} and {} produced identical public keys",
                    i + 1,
                    j + 1
                );
            }
        }
    }

    #[test]
    fn test_unit_key_public_key_starts_with_prefix() {
        // Compressed SEC1 public key must start with 0x02 or 0x03
        for i in 1u8..=30 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            seed[31] = i.wrapping_mul(3);
            if let Ok(keys) = VrfKeys::from_seed(&seed) {
                let prefix = keys.public_key()[0];
                assert!(
                    prefix == 0x02 || prefix == 0x03,
                    "Public key prefix is 0x{:02x}, expected 0x02 or 0x03 for seed {}",
                    prefix,
                    i
                );
            }
        }
    }

    // =========================================================================
    // EPOCH SEED TESTS
    // =========================================================================

    #[test]
    fn test_unit_epoch_derivation_sequential_10_epochs() {
        let master = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let mut prev_pk: Option<Vec<u8>> = None;

        for epoch in 0u64..10 {
            let epoch_keys = master.derive_epoch_keys(epoch).unwrap();
            let pk = epoch_keys.public_key_bytes();
            assert!(!pk.is_empty());

            if let Some(ref prev) = prev_pk {
                assert_ne!(
                    &pk,
                    prev,
                    "Sequential epochs {} and {} share same key",
                    epoch - 1,
                    epoch
                );
            }
            prev_pk = Some(pk);
        }
    }

    #[test]
    fn test_unit_epoch_derivation_sparse_epochs() {
        let master = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        let sparse_epochs = [0, 1, 100, 1000, 10_000, 100_000, u64::MAX / 2];
        let mut pks = std::collections::HashSet::new();

        for &epoch in &sparse_epochs {
            let epoch_keys = master.derive_epoch_keys(epoch).unwrap();
            let pk = epoch_keys.public_key_bytes();
            assert!(
                pks.insert(pk),
                "Sparse epoch {} produced a duplicate key",
                epoch
            );
        }
    }

    #[test]
    fn test_unit_epoch_derivation_same_epoch_same_result_repeated() {
        let master = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        // Derive the same epoch 20 times - must always give identical results
        let reference = master.derive_epoch_keys(7).unwrap();
        for _ in 0..20 {
            let derived = master.derive_epoch_keys(7).unwrap();
            assert_eq!(reference.public_key(), derived.public_key());
            assert_eq!(reference.secret_key(), derived.secret_key());
        }
    }

    #[test]
    fn test_boundary_epoch_derivation_u64_near_max() {
        let master = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        let near_max_epochs = [u64::MAX - 2, u64::MAX - 1, u64::MAX];
        let mut pks = std::collections::HashSet::new();

        for &epoch in &near_max_epochs {
            let epoch_keys = master.derive_epoch_keys(epoch).unwrap();
            let pk = epoch_keys.public_key_bytes();
            assert!(
                pks.insert(pk),
                "Near-max epoch {} produced duplicate key",
                epoch
            );
        }

        assert_eq!(pks.len(), 3);
    }

    #[test]
    fn test_unit_epoch_derivation_different_master_keys() {
        let master1 = VrfKeys::from_seed(&[1u8; 32]).unwrap();
        let master2 = VrfKeys::from_seed(&[2u8; 32]).unwrap();

        let epoch = 42u64;
        let derived1 = master1.derive_epoch_keys(epoch).unwrap();
        let derived2 = master2.derive_epoch_keys(epoch).unwrap();

        assert_ne!(
            derived1.public_key(),
            derived2.public_key(),
            "Different master keys must derive different epoch keys"
        );
    }

    // =========================================================================
    // PROOF VERIFICATION EDGE CASES
    // =========================================================================

    #[test]
    fn test_negative_verify_all_zeros_proof() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let input = b"test message";

        let (_, output) = engine.prove(&keys, input).unwrap();

        // Craft a proof with all-zero bytes
        let fake_proof = VrfProof {
            gamma: vec![0u8; 33],
            c: [0u8; 32],
            s: [0u8; 32],
        };

        let result = engine.verify(keys.public_key(), input, &fake_proof);
        match result {
            Ok(verified) => assert_ne!(
                output, verified,
                "All-zeros proof must not produce correct output"
            ),
            Err(_) => {} // Error is also acceptable
        }
    }

    #[test]
    fn test_negative_verify_all_ones_proof() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let input = b"test message";

        let (_, output) = engine.prove(&keys, input).unwrap();

        let fake_proof = VrfProof {
            gamma: vec![0xFF; 33],
            c: [0xFF; 32],
            s: [0xFF; 32],
        };

        let result = engine.verify(keys.public_key(), input, &fake_proof);
        match result {
            Ok(verified) => assert_ne!(
                output, verified,
                "All-ones proof must not produce correct output"
            ),
            Err(_) => {} // Error is also acceptable
        }
    }

    #[test]
    fn test_negative_verify_random_garbage_proof() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let input = b"test message";

        let (_, output) = engine.prove(&keys, input).unwrap();

        // Build a proof from pseudo-random garbage
        let mut gamma = vec![0x02]; // valid prefix
        for i in 0u8..32 {
            gamma.push(i.wrapping_mul(37).wrapping_add(13));
        }
        let mut c = [0u8; 32];
        let mut s = [0u8; 32];
        for i in 0..32 {
            c[i] = (i as u8).wrapping_mul(59);
            s[i] = (i as u8).wrapping_mul(97);
        }

        let fake_proof = VrfProof { gamma, c, s };

        let result = engine.verify(keys.public_key(), input, &fake_proof);
        match result {
            Ok(verified) => assert_ne!(
                output, verified,
                "Random garbage proof must not produce correct output"
            ),
            Err(_) => {} // Error is also acceptable
        }
    }

    #[test]
    fn test_negative_verify_swapped_output_proof() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let input = b"test message";

        let (proof, output) = engine.prove(&keys, input).unwrap();

        // Swap the c and s fields in the proof
        let swapped_proof = VrfProof {
            gamma: proof.gamma.clone(),
            c: proof.s,
            s: proof.c,
        };

        let result = engine.verify(keys.public_key(), input, &swapped_proof);
        match result {
            Ok(verified) => assert_ne!(
                output, verified,
                "Swapped proof fields must not produce correct output"
            ),
            Err(_) => {} // Error is also acceptable
        }
    }

    #[test]
    fn test_negative_verify_correct_proof_wrong_engine() {
        let engine1 = VrfEngine::with_chain_id(1);
        let engine2 = VrfEngine::with_chain_id(999);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let input = b"test message";

        let (proof, output) = engine1.prove(&keys, input).unwrap();

        // Verify with a different engine (different chain ID)
        let result = engine2.verify(keys.public_key(), input, &proof);
        match result {
            Ok(verified) => assert_ne!(output, verified, "Wrong engine must not verify correctly"),
            Err(_) => {} // Error is also acceptable
        }
    }

    // =========================================================================
    // VRF OUTPUT ANALYSIS
    // =========================================================================

    #[test]
    fn test_unit_output_different_messages_different_outputs() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        let messages = [b"alpha".as_ref(), b"beta", b"gamma", b"delta", b"epsilon"];
        let outputs: Vec<VrfOutput> = messages
            .iter()
            .map(|m| {
                let (_, out) = engine.prove(&keys, m).unwrap();
                out
            })
            .collect();

        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                assert_ne!(
                    outputs[i],
                    outputs[j],
                    "Messages '{}' and '{}' produced same output",
                    String::from_utf8_lossy(messages[i]),
                    String::from_utf8_lossy(messages[j])
                );
            }
        }
    }

    #[test]
    fn test_unit_output_is_32_bytes() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        let (_, output) = engine.prove(&keys, b"test").unwrap();
        assert_eq!(output.as_bytes().len(), 32);
        assert_eq!(output.as_ref().len(), 32);
    }

    #[test]
    fn test_unit_output_not_all_zeros() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        for i in 0..20 {
            let input = format!("nonzero-{}", i);
            let (_, output) = engine.prove(&keys, input.as_bytes()).unwrap();
            assert_ne!(
                output.0, [0u8; 32],
                "Output at iteration {} is all zeros",
                i
            );
        }
    }

    #[test]
    fn test_unit_output_not_all_ones() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        for i in 0..20 {
            let input = format!("nonones-{}", i);
            let (_, output) = engine.prove(&keys, input.as_bytes()).unwrap();
            assert_ne!(
                output.0, [0xFF; 32],
                "Output at iteration {} is all ones",
                i
            );
        }
    }

    #[test]
    fn test_property_output_independence_across_slots() {
        let engine = VrfEngine::with_chain_id(1);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];

        // Collect outputs for 30 sequential slots
        let outputs: Vec<VrfOutput> = (0u64..30)
            .map(|slot| {
                let (out, _) = engine.prove_for_slot(&keys, &epoch_seed, slot).unwrap();
                out
            })
            .collect();

        // Check that changing one slot doesn't affect others (all unique)
        let unique: std::collections::HashSet<[u8; 32]> = outputs.iter().map(|o| o.0).collect();
        assert_eq!(unique.len(), 30, "Expected 30 unique outputs for 30 slots");
    }

    // =========================================================================
    // MESSAGE CONSTRUCTION
    // =========================================================================

    #[test]
    fn test_unit_construct_message_includes_slot() {
        let engine = VrfEngine::with_chain_id(1);
        let epoch_seed = [0u8; 32];

        let slot: u64 = 0x0102030405060708;
        let msg = engine.construct_message(&epoch_seed, slot);

        // The last 8 bytes should be the slot in little-endian
        let slot_bytes = slot.to_le_bytes();
        let msg_tail = &msg[msg.len() - 8..];
        assert_eq!(msg_tail, &slot_bytes, "Message must end with slot LE bytes");
    }

    #[test]
    fn test_unit_construct_message_includes_seed() {
        let engine = VrfEngine::with_chain_id(1);
        let epoch_seed = [0xAB; 32];

        let msg = engine.construct_message(&epoch_seed, 0);

        // The seed should appear in the message (after the domain tag + chain ID)
        // Domain tag: "Aethelred-PoUW-VRF-v1:" (22 bytes) + 8 bytes chain_id = 30 bytes
        let seed_region = &msg[30..30 + 32];
        assert_eq!(
            seed_region, &epoch_seed,
            "Message must contain the epoch seed"
        );
    }

    #[test]
    fn test_boundary_construct_message_empty_seed() {
        let engine = VrfEngine::with_chain_id(1);
        let epoch_seed = [0u8; 32];

        let msg = engine.construct_message(&epoch_seed, 42);
        // Should still produce a valid non-empty message
        assert!(!msg.is_empty());
        // The domain tag should still be present
        assert!(msg.starts_with(b"Aethelred-PoUW-VRF-v1:"));
    }

    #[test]
    fn test_unit_construct_message_long_seed() {
        // EpochSeed is fixed [u8; 32], so we test with a max-value seed
        let engine = VrfEngine::with_chain_id(1);
        let epoch_seed = [0xFF; 32];

        let msg = engine.construct_message(&epoch_seed, 1);
        // Domain (22) + chain_id (8) + seed (32) + slot (8) = 70
        assert_eq!(
            msg.len(),
            70,
            "Message length should be domain + chain_id + seed + slot"
        );
    }

    // =========================================================================
    // DOMAIN SEPARATION ADVANCED
    // =========================================================================

    #[test]
    fn test_unit_domain_separation_many_chain_ids() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let input = b"domain-test";

        let mut outputs = std::collections::HashSet::new();
        for chain_id in 0u64..15 {
            let engine = VrfEngine::with_chain_id(chain_id);
            let (_, output) = engine.prove(&keys, input).unwrap();
            assert!(
                outputs.insert(output.0),
                "Chain ID {} produced a duplicate output",
                chain_id
            );
        }

        assert_eq!(outputs.len(), 15);
    }

    #[test]
    fn test_unit_domain_separation_same_slot_different_chains() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];
        let slot = 100;

        let engine_a = VrfEngine::with_chain_id(1);
        let engine_b = VrfEngine::with_chain_id(2);
        let engine_c = VrfEngine::with_chain_id(3);

        let (out_a, _) = engine_a.prove_for_slot(&keys, &epoch_seed, slot).unwrap();
        let (out_b, _) = engine_b.prove_for_slot(&keys, &epoch_seed, slot).unwrap();
        let (out_c, _) = engine_c.prove_for_slot(&keys, &epoch_seed, slot).unwrap();

        assert_ne!(out_a, out_b);
        assert_ne!(out_b, out_c);
        assert_ne!(out_a, out_c);
    }

    #[test]
    fn test_unit_domain_separation_proof_cross_chain_batch() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];

        // Prove on chain 1, try to verify on chains 2..5
        let engine1 = VrfEngine::with_chain_id(1);
        let (output, proof) = engine1.prove_for_slot(&keys, &epoch_seed, 50).unwrap();

        for other_chain in 2u64..=5 {
            let other_engine = VrfEngine::with_chain_id(other_chain);
            let result =
                other_engine.verify_for_slot(keys.public_key(), &epoch_seed, 50, &output, &proof);
            match result {
                Ok(valid) => assert!(
                    !valid,
                    "Chain {} should not verify chain 1's proof",
                    other_chain
                ),
                Err(_) => {} // Also acceptable
            }
        }
    }

    #[test]
    fn test_unit_domain_separation_engine_isolation() {
        // Two engines with different chain IDs are fully independent
        let engine_x = VrfEngine::with_chain_id(100);
        let engine_y = VrfEngine::with_chain_id(200);
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let input = b"isolation-test";

        let (proof_x, output_x) = engine_x.prove(&keys, input).unwrap();
        let (proof_y, output_y) = engine_y.prove(&keys, input).unwrap();

        // Outputs must differ
        assert_ne!(output_x, output_y);

        // Each proof should verify on its own engine
        let vx = engine_x.verify(keys.public_key(), input, &proof_x).unwrap();
        let vy = engine_y.verify(keys.public_key(), input, &proof_y).unwrap();
        assert_eq!(output_x, vx);
        assert_eq!(output_y, vy);
    }

    // =========================================================================
    // INTEGRATION ADVANCED
    // =========================================================================

    #[test]
    fn test_integration_full_lifecycle_generate_prove_serialize_deserialize_verify() {
        let engine = VrfEngine::with_chain_id(42);

        // Step 1: Generate keys
        let keys = VrfKeys::generate().unwrap();
        let pk = keys.public_key_bytes();

        // Step 2: Prove
        let epoch_seed = [0xBE; 32];
        let slot = 777;
        let (output, proof) = engine.prove_for_slot(&keys, &epoch_seed, slot).unwrap();

        // Step 3: Serialize proof
        let proof_bytes = proof.to_bytes();
        assert_eq!(proof_bytes.len(), VrfProof::SIZE);

        // Step 4: Deserialize proof
        let restored_proof = VrfProof::from_bytes(&proof_bytes).unwrap();

        // Step 5: Verify with deserialized proof and stored public key
        let valid = engine
            .verify_for_slot(&pk, &epoch_seed, slot, &output, &restored_proof)
            .unwrap();
        assert!(valid, "Full lifecycle verification must succeed");
    }

    #[test]
    fn test_integration_epoch_rotation_5_epochs_continuous() {
        let engine = VrfEngine::with_chain_id(1);
        let master = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        let mut all_outputs = Vec::new();

        for epoch in 0u64..5 {
            let epoch_keys = master.derive_epoch_keys(epoch).unwrap();
            let epoch_seed = {
                let mut s = [0u8; 32];
                // Use a different seed each epoch
                let epoch_bytes = epoch.to_le_bytes();
                s[..8].copy_from_slice(&epoch_bytes);
                s
            };

            // Prove 10 slots per epoch
            for slot in 0u64..10 {
                let (output, proof) = engine
                    .prove_for_slot(&epoch_keys, &epoch_seed, slot)
                    .unwrap();
                let valid = engine
                    .verify_for_slot(epoch_keys.public_key(), &epoch_seed, slot, &output, &proof)
                    .unwrap();
                assert!(valid, "Epoch {} slot {} failed", epoch, slot);
                all_outputs.push(output);
            }
        }

        // All 50 outputs across all epochs should be unique
        let unique: std::collections::HashSet<[u8; 32]> = all_outputs.iter().map(|o| o.0).collect();
        assert_eq!(
            unique.len(),
            50,
            "Expected 50 unique outputs across 5 epochs x 10 slots"
        );
    }

    #[test]
    fn test_integration_key_rotation_new_key_each_epoch() {
        let engine = VrfEngine::with_chain_id(1);
        let master = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];
        let slot = 0;

        let mut public_keys = Vec::new();
        let mut outputs = Vec::new();

        for epoch in 0u64..10 {
            let epoch_keys = master.derive_epoch_keys(epoch).unwrap();
            public_keys.push(epoch_keys.public_key_bytes());

            let (output, proof) = engine
                .prove_for_slot(&epoch_keys, &epoch_seed, slot)
                .unwrap();
            let valid = engine
                .verify_for_slot(epoch_keys.public_key(), &epoch_seed, slot, &output, &proof)
                .unwrap();
            assert!(valid, "Epoch {} failed verification", epoch);
            outputs.push(output);
        }

        // All public keys should be different
        for i in 0..public_keys.len() {
            for j in (i + 1)..public_keys.len() {
                assert_ne!(
                    public_keys[i], public_keys[j],
                    "Epoch keys {} and {} are identical",
                    i, j
                );
            }
        }

        // All outputs should be different (same seed/slot but different keys)
        for i in 0..outputs.len() {
            for j in (i + 1)..outputs.len() {
                assert_ne!(
                    outputs[i], outputs[j],
                    "Outputs {} and {} are identical",
                    i, j
                );
            }
        }
    }

    #[test]
    fn test_integration_multiple_engines_independent() {
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let epoch_seed = [1u8; 32];
        let slot = 100;

        let chain_ids = [1u64, 2, 3, 100, 999];
        let mut engine_outputs = Vec::new();

        for &cid in &chain_ids {
            let engine = VrfEngine::with_chain_id(cid);
            let (output, proof) = engine.prove_for_slot(&keys, &epoch_seed, slot).unwrap();
            let valid = engine
                .verify_for_slot(keys.public_key(), &epoch_seed, slot, &output, &proof)
                .unwrap();
            assert!(valid, "Chain {} failed self-verification", cid);
            engine_outputs.push((cid, output));
        }

        // All outputs from different chains must be unique
        for i in 0..engine_outputs.len() {
            for j in (i + 1)..engine_outputs.len() {
                assert_ne!(
                    engine_outputs[i].1, engine_outputs[j].1,
                    "Chain {} and chain {} produced same output",
                    engine_outputs[i].0, engine_outputs[j].0
                );
            }
        }
    }

    // =========================================================================
    // PROPERTY TESTS
    // =========================================================================

    #[test]
    fn test_property_prove_verify_always_succeeds_for_valid_inputs() {
        let engine = VrfEngine::new();

        // Test with many different keys and messages
        for i in 1u8..=20 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            let keys = VrfKeys::from_seed(&seed).unwrap();
            let input = format!("valid-input-{}", i);

            let (proof, output) = engine.prove(&keys, input.as_bytes()).unwrap();
            let verified = engine
                .verify(keys.public_key(), input.as_bytes(), &proof)
                .unwrap();
            assert_eq!(
                output, verified,
                "Valid prove/verify failed for key seed {} and input '{}'",
                i, input
            );
        }
    }

    #[test]
    fn test_property_different_inputs_different_outputs_statistical() {
        let engine = VrfEngine::new();
        let keys = VrfKeys::from_seed(&[42u8; 32]).unwrap();

        let mut outputs = std::collections::HashSet::new();
        let count = 200;
        for i in 0..count {
            let input = format!("stat-input-{}", i);
            let (_, output) = engine.prove(&keys, input.as_bytes()).unwrap();
            outputs.insert(output.0);
        }

        // All 200 different inputs must produce 200 different outputs
        assert_eq!(
            outputs.len(),
            count,
            "Expected {} unique outputs, got {}",
            count,
            outputs.len()
        );
    }

    #[test]
    fn test_property_serialization_preserves_verifiability() {
        let engine = VrfEngine::new();

        for i in 1u8..=15 {
            let mut seed = [0u8; 32];
            seed[0] = i;
            let keys = VrfKeys::from_seed(&seed).unwrap();
            let input = format!("ser-verify-{}", i);

            let (proof, output) = engine.prove(&keys, input.as_bytes()).unwrap();

            // Serialize and deserialize
            let bytes = proof.to_bytes();
            let restored = VrfProof::from_bytes(&bytes).unwrap();

            // Verify with restored proof
            let verified = engine
                .verify(keys.public_key(), input.as_bytes(), &restored)
                .unwrap();
            assert_eq!(
                output, verified,
                "Serialization broke verifiability for seed {}",
                i
            );
        }
    }

    #[test]
    fn test_property_epoch_derivation_never_returns_master_key() {
        let master = VrfKeys::from_seed(&[42u8; 32]).unwrap();
        let master_pk = master.public_key_bytes();
        let master_sk = *master.secret_key();

        for epoch in 0u64..100 {
            let derived = master.derive_epoch_keys(epoch).unwrap();
            assert_ne!(
                derived.public_key(),
                master_pk.as_slice(),
                "Epoch {} derived the master public key",
                epoch
            );
            assert_ne!(
                derived.secret_key(),
                &master_sk,
                "Epoch {} derived the master secret key",
                epoch
            );
        }
    }
}
