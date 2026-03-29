//! ECDSA secp256k1 Digital Signatures
//!
//! Production implementation of ECDSA on the secp256k1 curve using the `k256`
//! crate for Bitcoin/Ethereum compatibility. Used as the classical component
//! of hybrid signatures.
//!
//! # Security Note
//!
//! ECDSA on secp256k1 provides ~128-bit classical security but is
//! vulnerable to quantum attacks (Shor's algorithm). In Aethelred,
//! it is paired with Dilithium3 for quantum resistance.
//!
//! # Key Sizes
//!
//! | Parameter        | Size (bytes) |
//! |------------------|--------------|
//! | Public Key       | 33 (compressed) / 65 (uncompressed) |
//! | Secret Key       | 32           |
//! | Signature        | 64 (compact) / 71 (DER) |

use super::{CryptoError, CryptoResult};
use k256::ecdsa::{
    signature::hazmat::PrehashVerifier, RecoveryId, Signature as K256Signature, SigningKey,
    VerifyingKey,
};

use sha2::{Digest, Sha256};
use sha3::Keccak256;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// ECDSA public key (compressed format)
#[derive(Clone, PartialEq, Eq)]
pub struct EcdsaPublicKey {
    /// Compressed public key (33 bytes)
    bytes: [u8; 33],
}

impl EcdsaPublicKey {
    /// Compressed public key size
    pub const SIZE: usize = 33;

    /// Create from compressed bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidPublicKeyLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        // Validate prefix byte (0x02 or 0x03 for compressed)
        if bytes[0] != 0x02 && bytes[0] != 0x03 {
            return Err(CryptoError::InvalidKeyFormat(
                "Invalid compressed public key prefix".into(),
            ));
        }

        // Validate that the bytes represent a valid point on secp256k1
        VerifyingKey::from_sec1_bytes(bytes).map_err(|_| {
            CryptoError::InvalidKeyFormat("Point is not on the secp256k1 curve".into())
        })?;

        let mut key = [0u8; 33];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Create from uncompressed bytes (65 bytes) by compressing
    pub fn from_uncompressed(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != 65 {
            return Err(CryptoError::InvalidPublicKeyLength {
                expected: 65,
                actual: bytes.len(),
            });
        }

        if bytes[0] != 0x04 {
            return Err(CryptoError::InvalidKeyFormat(
                "Invalid uncompressed public key prefix".into(),
            ));
        }

        // Parse as a verifying key to validate and compress properly
        let vk = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|_| CryptoError::InvalidKeyFormat("Invalid uncompressed public key".into()))?;

        let compressed = vk.to_encoded_point(true);
        let mut key = [0u8; 33];
        key.copy_from_slice(compressed.as_bytes());
        Ok(Self { bytes: key })
    }

    /// Get raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get as fixed array
    pub fn to_bytes(&self) -> [u8; 33] {
        self.bytes
    }

    /// Compute Ethereum-style address (last 20 bytes of Keccak256(uncompressed_pubkey_without_prefix))
    pub fn to_eth_address(&self) -> [u8; 20] {
        // Decompress the public key to get the full 65-byte uncompressed form
        let vk = VerifyingKey::from_sec1_bytes(&self.bytes)
            .expect("EcdsaPublicKey always contains valid key bytes");
        let uncompressed = vk.to_encoded_point(false);
        // Keccak256 of the 64-byte public key (without 0x04 prefix)
        let hash = Keccak256::digest(&uncompressed.as_bytes()[1..]);
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&hash[12..32]);
        addr
    }

    /// Compute fingerprint (first 16 bytes of SHA256 hash)
    pub fn fingerprint(&self) -> [u8; 16] {
        let hash = Sha256::digest(self.bytes);
        let mut fp = [0u8; 16];
        fp.copy_from_slice(&hash[..16]);
        fp
    }
}

impl fmt::Debug for EcdsaPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaPublicKey")
            .field("compressed", &hex::encode(self.bytes))
            .finish()
    }
}

/// ECDSA secret key (zeroized on drop)
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct EcdsaSecretKey {
    bytes: [u8; 32],
}

impl EcdsaSecretKey {
    /// Secret key size
    pub const SIZE: usize = 32;

    /// Create from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::SIZE {
            return Err(CryptoError::InvalidSecretKeyLength {
                expected: Self::SIZE,
                actual: bytes.len(),
            });
        }

        // Validate scalar is in valid range by attempting to create a k256 SigningKey
        SigningKey::from_slice(bytes).map_err(|_| {
            CryptoError::InvalidKeyFormat("Secret key is not a valid secp256k1 scalar".into())
        })?;

        let mut key = [0u8; 32];
        key.copy_from_slice(bytes);
        Ok(Self { bytes: key })
    }

    /// Generate random secret key
    pub fn generate() -> CryptoResult<Self> {
        let signing_key = SigningKey::random(&mut rand::thread_rng());
        let bytes = signing_key.to_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self { bytes: key })
    }

    /// Get raw bytes (sensitive - use with caution)
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Derive public key
    pub fn public_key(&self) -> CryptoResult<EcdsaPublicKey> {
        derive_public_key(self)
    }
}

impl fmt::Debug for EcdsaSecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSecretKey")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}

/// ECDSA signature (compact format: r || s)
#[derive(Clone, PartialEq, Eq)]
pub struct EcdsaSignature {
    /// R component (32 bytes)
    r: [u8; 32],
    /// S component (32 bytes)
    s: [u8; 32],
    /// Recovery ID (0-3) for public key recovery
    recovery_id: Option<u8>,
}

impl EcdsaSignature {
    /// Compact signature size (r || s)
    pub const COMPACT_SIZE: usize = 64;

    /// Create from compact bytes (r || s)
    pub fn from_compact(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != Self::COMPACT_SIZE {
            return Err(CryptoError::InvalidSignatureLength {
                expected: Self::COMPACT_SIZE,
                actual: bytes.len(),
            });
        }

        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[..32]);
        s.copy_from_slice(&bytes[32..]);

        Ok(Self {
            r,
            s,
            recovery_id: None,
        })
    }

    /// Create from compact bytes with recovery ID
    pub fn from_compact_recoverable(bytes: &[u8], recovery_id: u8) -> CryptoResult<Self> {
        if recovery_id > 3 {
            return Err(CryptoError::InvalidKeyFormat(
                "Recovery ID must be 0-3".into(),
            ));
        }

        let mut sig = Self::from_compact(bytes)?;
        sig.recovery_id = Some(recovery_id);
        Ok(sig)
    }

    /// Create from DER-encoded bytes
    pub fn from_der(bytes: &[u8]) -> CryptoResult<Self> {
        // Parse via k256 for correct DER handling
        let k256_sig = K256Signature::from_der(bytes)
            .map_err(|_| CryptoError::InvalidKeyFormat("Invalid DER signature".into()))?;

        let sig_bytes = k256_sig.to_bytes();
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig_bytes[..32]);
        s.copy_from_slice(&sig_bytes[32..]);

        Ok(Self {
            r,
            s,
            recovery_id: None,
        })
    }

    /// Get compact bytes (r || s)
    pub fn to_compact(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[..32].copy_from_slice(&self.r);
        bytes[32..].copy_from_slice(&self.s);
        bytes
    }

    /// Get R component
    pub fn r(&self) -> &[u8; 32] {
        &self.r
    }

    /// Get S component
    pub fn s(&self) -> &[u8; 32] {
        &self.s
    }

    /// Get recovery ID if available
    pub fn recovery_id(&self) -> Option<u8> {
        self.recovery_id
    }

    /// Normalize S to low-S form (BIP-62 / EIP-2)
    ///
    /// Ensures S ≤ n/2 to prevent transaction malleability.
    /// If S > n/2, replaces S with n - S.
    pub fn normalize_s(&mut self) {
        let compact = self.to_compact();
        if let Ok(k256_sig) = K256Signature::from_slice(&compact) {
            if let Some(normalized) = k256_sig.normalize_s() {
                let norm_bytes = normalized.to_bytes();
                self.r.copy_from_slice(&norm_bytes[..32]);
                self.s.copy_from_slice(&norm_bytes[32..]);
                // Flip recovery ID if present
                if let Some(rid) = self.recovery_id {
                    self.recovery_id = Some(rid ^ 1);
                }
            }
        }
    }
}

impl fmt::Debug for EcdsaSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSignature")
            .field("r", &hex::encode(self.r))
            .field("s", &hex::encode(self.s))
            .field("recovery_id", &self.recovery_id)
            .finish()
    }
}

/// ECDSA keypair
#[derive(Clone)]
pub struct EcdsaKeyPair {
    pub public_key: EcdsaPublicKey,
    secret_key: EcdsaSecretKey,
}

impl EcdsaKeyPair {
    /// Generate a new keypair
    pub fn generate() -> CryptoResult<Self> {
        let secret_key = EcdsaSecretKey::generate()?;
        let public_key = secret_key.public_key()?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Create from existing secret key
    pub fn from_secret_key(secret_key: EcdsaSecretKey) -> CryptoResult<Self> {
        let public_key = secret_key.public_key()?;
        Ok(Self {
            public_key,
            secret_key,
        })
    }

    /// Get the public key
    pub fn public_key(&self) -> &EcdsaPublicKey {
        &self.public_key
    }

    /// Get the secret key (sensitive)
    pub fn secret_key(&self) -> &EcdsaSecretKey {
        &self.secret_key
    }

    /// Sign a message (hashes internally with SHA256)
    pub fn sign(&self, message: &[u8]) -> CryptoResult<EcdsaSignature> {
        sign(message, &self.secret_key)
    }

    /// Sign a pre-hashed message (32 bytes)
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> CryptoResult<EcdsaSignature> {
        sign_prehash(hash, &self.secret_key)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &EcdsaSignature) -> CryptoResult<bool> {
        verify(message, signature, &self.public_key)
    }
}

impl fmt::Debug for EcdsaKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaKeyPair")
            .field("public_key", &self.public_key)
            .field("secret_key", &"[REDACTED]")
            .finish()
    }
}

/// Derive public key from secret key using real EC scalar multiplication
pub fn derive_public_key(secret_key: &EcdsaSecretKey) -> CryptoResult<EcdsaPublicKey> {
    let signing_key = SigningKey::from_slice(secret_key.as_bytes())
        .map_err(|_| CryptoError::InvalidKeyFormat("Invalid secp256k1 secret key scalar".into()))?;

    let verifying_key = signing_key.verifying_key();
    let compressed = verifying_key.to_encoded_point(true);

    let mut pk_bytes = [0u8; 33];
    pk_bytes.copy_from_slice(compressed.as_bytes());

    // We know this is valid because we just derived it from a valid signing key
    Ok(EcdsaPublicKey { bytes: pk_bytes })
}

/// Sign a message with SHA256 hashing
pub fn sign(message: &[u8], secret_key: &EcdsaSecretKey) -> CryptoResult<EcdsaSignature> {
    let hash = Sha256::digest(message);
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash);
    sign_prehash(&hash_array, secret_key)
}

/// Sign a pre-hashed message (32 bytes) using RFC 6979 deterministic k
pub fn sign_prehash(hash: &[u8; 32], secret_key: &EcdsaSecretKey) -> CryptoResult<EcdsaSignature> {
    let signing_key = SigningKey::from_slice(secret_key.as_bytes()).map_err(|_| {
        CryptoError::InvalidKeyFormat("Invalid secp256k1 secret key for signing".into())
    })?;

    // sign_prehash_recoverable uses RFC 6979 deterministic nonce generation
    let (signature, recovery_id) = signing_key
        .sign_prehash_recoverable(hash)
        .map_err(|e| CryptoError::SigningFailed(format!("ECDSA signing failed: {}", e)))?;

    let sig_bytes = signature.to_bytes();
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(&sig_bytes[..32]);
    s.copy_from_slice(&sig_bytes[32..]);

    Ok(EcdsaSignature {
        r,
        s,
        recovery_id: Some(recovery_id.to_byte()),
    })
}

/// Verify a signature
pub fn verify(
    message: &[u8],
    signature: &EcdsaSignature,
    public_key: &EcdsaPublicKey,
) -> CryptoResult<bool> {
    let hash = Sha256::digest(message);
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&hash);
    verify_prehash(&hash_array, signature, public_key)
}

/// Verify a signature on a pre-hashed message using real ECDSA verification
pub fn verify_prehash(
    hash: &[u8; 32],
    signature: &EcdsaSignature,
    public_key: &EcdsaPublicKey,
) -> CryptoResult<bool> {
    // Parse the verifying key
    let vk = VerifyingKey::from_sec1_bytes(public_key.as_bytes()).map_err(|_| {
        CryptoError::InvalidKeyFormat("Invalid secp256k1 public key for verification".into())
    })?;

    // Reconstruct the k256 signature from r || s
    let compact = signature.to_compact();
    let k256_sig = K256Signature::from_slice(&compact)
        .map_err(|_| CryptoError::InvalidKeyFormat("Invalid ECDSA signature components".into()))?;

    // Perform the actual ECDSA verification: u1*G + u2*P == R
    match vk.verify_prehash(hash, &k256_sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Recover public key from signature and message using real EC point recovery
pub fn recover_public_key(
    message: &[u8],
    signature: &EcdsaSignature,
) -> CryptoResult<EcdsaPublicKey> {
    let recovery_id_byte = signature.recovery_id.ok_or_else(|| {
        CryptoError::InvalidKeyFormat("Recovery ID required for key recovery".into())
    })?;

    let recovery_id = RecoveryId::from_byte(recovery_id_byte).ok_or_else(|| {
        CryptoError::InvalidKeyFormat(format!("Invalid recovery ID: {}", recovery_id_byte))
    })?;

    let hash = Sha256::digest(message);

    // Reconstruct the k256 signature
    let compact = signature.to_compact();
    let k256_sig = K256Signature::from_slice(&compact).map_err(|_| {
        CryptoError::InvalidKeyFormat("Invalid ECDSA signature for recovery".into())
    })?;

    // Perform real EC public key recovery
    let recovered_key =
        VerifyingKey::recover_from_prehash(&hash, &k256_sig, recovery_id).map_err(|_| {
            CryptoError::InvalidKeyFormat("Failed to recover public key from signature".into())
        })?;

    let compressed = recovered_key.to_encoded_point(true);
    let mut pk_bytes = [0u8; 33];
    pk_bytes.copy_from_slice(compressed.as_bytes());

    Ok(EcdsaPublicKey { bytes: pk_bytes })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let keypair = EcdsaKeyPair::generate().unwrap();
        assert_eq!(keypair.public_key().as_bytes().len(), EcdsaPublicKey::SIZE);
    }

    #[test]
    fn test_sign_verify() {
        let keypair = EcdsaKeyPair::generate().unwrap();
        let message = b"Test message for ECDSA";

        let signature = keypair.sign(message).unwrap();
        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(is_valid, "Valid signature must verify");
    }

    #[test]
    fn test_sign_verify_wrong_message() {
        let keypair = EcdsaKeyPair::generate().unwrap();
        let signature = keypair.sign(b"correct message").unwrap();
        let is_valid = keypair.verify(b"wrong message", &signature).unwrap();
        assert!(!is_valid, "Signature must not verify with wrong message");
    }

    #[test]
    fn test_sign_verify_wrong_key() {
        let keypair1 = EcdsaKeyPair::generate().unwrap();
        let keypair2 = EcdsaKeyPair::generate().unwrap();
        let message = b"Test message";

        let signature = keypair1.sign(message).unwrap();
        let is_valid = verify(message, &signature, keypair2.public_key()).unwrap();
        assert!(!is_valid, "Signature must not verify with wrong public key");
    }

    #[test]
    fn test_deterministic_signing() {
        let keypair = EcdsaKeyPair::generate().unwrap();
        let message = b"Deterministic test";

        let sig1 = keypair.sign(message).unwrap();
        let sig2 = keypair.sign(message).unwrap();
        // RFC 6979 guarantees deterministic signatures
        assert_eq!(sig1.r(), sig2.r(), "RFC 6979: R must be deterministic");
        assert_eq!(sig1.s(), sig2.s(), "RFC 6979: S must be deterministic");
    }

    #[test]
    fn test_compact_signature() {
        let keypair = EcdsaKeyPair::generate().unwrap();
        let message = b"Test";

        let signature = keypair.sign(message).unwrap();
        let compact = signature.to_compact();
        assert_eq!(compact.len(), EcdsaSignature::COMPACT_SIZE);

        let restored = EcdsaSignature::from_compact(&compact).unwrap();
        assert_eq!(restored.r(), signature.r());
        assert_eq!(restored.s(), signature.s());
    }

    #[test]
    fn test_public_key_formats() {
        let keypair = EcdsaKeyPair::generate().unwrap();
        let pk = keypair.public_key();

        // Compressed format should start with 0x02 or 0x03
        assert!(pk.as_bytes()[0] == 0x02 || pk.as_bytes()[0] == 0x03);
    }

    #[test]
    fn test_public_key_recovery() {
        let keypair = EcdsaKeyPair::generate().unwrap();
        let message = b"Recovery test message";

        let signature = keypair.sign(message).unwrap();
        assert!(signature.recovery_id().is_some());

        let recovered = recover_public_key(message, &signature).unwrap();
        assert_eq!(
            recovered.as_bytes(),
            keypair.public_key().as_bytes(),
            "Recovered key must match original"
        );
    }

    #[test]
    fn test_eth_address_derivation() {
        let keypair = EcdsaKeyPair::generate().unwrap();
        let addr = keypair.public_key().to_eth_address();
        assert_eq!(addr.len(), 20);
        // Address should not be all zeros (statistically impossible)
        assert!(addr.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_normalize_s() {
        let keypair = EcdsaKeyPair::generate().unwrap();
        let message = b"Normalization test";

        let mut signature = keypair.sign(message).unwrap();
        signature.normalize_s();

        // After normalization, signature must still verify
        let is_valid = keypair.verify(message, &signature).unwrap();
        assert!(is_valid, "Normalized signature must still verify");
    }

    #[test]
    fn test_invalid_secret_key_zero() {
        let zero_bytes = [0u8; 32];
        let result = EcdsaSecretKey::from_bytes(&zero_bytes);
        assert!(result.is_err(), "Zero secret key must be rejected");
    }

    #[test]
    fn test_from_secret_key_roundtrip() {
        let keypair1 = EcdsaKeyPair::generate().unwrap();
        let sk_bytes = keypair1.secret_key().as_bytes().to_vec();

        let sk2 = EcdsaSecretKey::from_bytes(&sk_bytes).unwrap();
        let keypair2 = EcdsaKeyPair::from_secret_key(sk2).unwrap();

        assert_eq!(
            keypair1.public_key().as_bytes(),
            keypair2.public_key().as_bytes(),
            "Same secret key must produce same public key"
        );
    }
}
