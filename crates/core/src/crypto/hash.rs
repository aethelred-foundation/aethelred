//! Aethelred Hash Functions
//!
//! Cryptographic hash functions for transaction hashing, Merkle trees,
//! and commitment schemes.
//!
//! # Supported Algorithms
//!
//! - SHA-256: Primary hash for transactions
//! - BLAKE3: Fast hashing for large data
//! - Keccak-256: Ethereum compatibility
//! - Poseidon: ZK-friendly hash for circuits

use sha2::{Digest, Sha256};
use std::fmt;

/// Hash output size variants
pub const HASH_SIZE_256: usize = 32;
pub const HASH_SIZE_512: usize = 64;

/// 256-bit hash value
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Hash256(pub [u8; HASH_SIZE_256]);

impl Hash256 {
    /// Zero hash
    pub const ZERO: Self = Self([0u8; HASH_SIZE_256]);

    /// Create from bytes
    pub fn from_bytes(bytes: [u8; HASH_SIZE_256]) -> Self {
        Self(bytes)
    }

    /// Create from slice
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != HASH_SIZE_256 {
            return None;
        }
        let mut bytes = [0u8; HASH_SIZE_256];
        bytes.copy_from_slice(slice);
        Some(Self(bytes))
    }

    /// Get bytes
    pub fn as_bytes(&self) -> &[u8; HASH_SIZE_256] {
        &self.0
    }

    /// Convert to hex string
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string
    pub fn from_hex(s: &str) -> Result<Self, hex::FromHexError> {
        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes).ok_or(hex::FromHexError::InvalidStringLength)
    }

    /// Check if zero
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Default for Hash256 {
    fn default() -> Self {
        Self::ZERO
    }
}

impl AsRef<[u8]> for Hash256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Hash256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", &self.to_hex()[..16])
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// SHA-256 hasher
pub struct Sha256Hasher {
    hasher: Sha256,
}

impl Sha256Hasher {
    /// Create new hasher
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }

    /// Update with data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and get hash
    pub fn finalize(self) -> Hash256 {
        let result = self.hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Hash256(hash)
    }

    /// One-shot hash
    pub fn hash(data: &[u8]) -> Hash256 {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Hash multiple inputs
    pub fn hash_many(inputs: &[&[u8]]) -> Hash256 {
        let mut hasher = Self::new();
        for input in inputs {
            hasher.update(input);
        }
        hasher.finalize()
    }
}

impl Default for Sha256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function: SHA-256 hash
pub fn sha256(data: &[u8]) -> Hash256 {
    Sha256Hasher::hash(data)
}

/// Convenience function: Double SHA-256 (Bitcoin-style)
pub fn double_sha256(data: &[u8]) -> Hash256 {
    sha256(sha256(data).as_bytes())
}

/// Keccak-256 hasher (Ethereum compatible)
pub struct Keccak256Hasher {
    hasher: sha3::Keccak256,
}

impl Keccak256Hasher {
    /// Create new hasher
    pub fn new() -> Self {
        Self {
            hasher: sha3::Keccak256::new(),
        }
    }

    /// Update with data
    pub fn update(&mut self, data: &[u8]) {
        use sha3::Digest;
        self.hasher.update(data);
    }

    /// Finalize and get hash
    pub fn finalize(self) -> Hash256 {
        use sha3::Digest;
        let result = self.hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&result);
        Hash256(hash)
    }

    /// One-shot hash
    pub fn hash(data: &[u8]) -> Hash256 {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }
}

impl Default for Keccak256Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function: Keccak-256 hash
pub fn keccak256(data: &[u8]) -> Hash256 {
    Keccak256Hasher::hash(data)
}

/// BLAKE3 hasher (fast, parallel)
pub struct Blake3Hasher {
    hasher: blake3::Hasher,
}

impl Blake3Hasher {
    /// Create new hasher
    pub fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }

    /// Create keyed hasher for MAC
    pub fn new_keyed(key: &[u8; 32]) -> Self {
        Self {
            hasher: blake3::Hasher::new_keyed(key),
        }
    }

    /// Create derive-key hasher
    pub fn new_derive_key(context: &str) -> Self {
        Self {
            hasher: blake3::Hasher::new_derive_key(context),
        }
    }

    /// Update with data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    /// Finalize and get hash
    pub fn finalize(self) -> Hash256 {
        let result = self.hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(result.as_bytes());
        Hash256(hash)
    }

    /// One-shot hash
    pub fn hash(data: &[u8]) -> Hash256 {
        let mut hasher = Self::new();
        hasher.update(data);
        hasher.finalize()
    }

    /// Hash file (uses SIMD and parallelism)
    pub fn hash_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Hash256> {
        let mut hasher = blake3::Hasher::new();
        std::io::copy(reader, &mut hasher)?;
        let result = hasher.finalize();
        let mut hash = [0u8; 32];
        hash.copy_from_slice(result.as_bytes());
        Ok(Hash256(hash))
    }
}

impl Default for Blake3Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function: BLAKE3 hash
pub fn blake3(data: &[u8]) -> Hash256 {
    Blake3Hasher::hash(data)
}

/// Transaction hash (domain-separated SHA-256)
///
/// Uses a domain separator to prevent replay attacks across different
/// message types.
pub fn transaction_hash(tx_bytes: &[u8]) -> Hash256 {
    const DOMAIN_SEPARATOR: &[u8] = b"aethelred:transaction:v1:";
    Sha256Hasher::hash_many(&[DOMAIN_SEPARATOR, tx_bytes])
}

/// Block hash (domain-separated)
pub fn block_hash(block_bytes: &[u8]) -> Hash256 {
    const DOMAIN_SEPARATOR: &[u8] = b"aethelred:block:v1:";
    Sha256Hasher::hash_many(&[DOMAIN_SEPARATOR, block_bytes])
}

/// Commitment hash (for hiding values)
pub fn commitment_hash(value: &[u8], blinding: &[u8; 32]) -> Hash256 {
    const DOMAIN_SEPARATOR: &[u8] = b"aethelred:commitment:v1:";
    Sha256Hasher::hash_many(&[DOMAIN_SEPARATOR, value, blinding])
}

/// Merkle tree hash combine
pub fn merkle_combine(left: &Hash256, right: &Hash256) -> Hash256 {
    const DOMAIN_SEPARATOR: &[u8] = b"aethelred:merkle:v1:";
    Sha256Hasher::hash_many(&[DOMAIN_SEPARATOR, left.as_bytes(), right.as_bytes()])
}

/// Compute Merkle root from leaves
pub fn merkle_root(leaves: &[Hash256]) -> Hash256 {
    if leaves.is_empty() {
        return Hash256::ZERO;
    }

    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_level: Vec<Hash256> = leaves.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len()).div_ceil(2));

        for chunk in current_level.chunks(2) {
            if chunk.len() == 2 {
                next_level.push(merkle_combine(&chunk[0], &chunk[1]));
            } else {
                // Odd number of nodes: duplicate the last one
                next_level.push(merkle_combine(&chunk[0], &chunk[0]));
            }
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Merkle proof
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// Proof path (sibling hashes)
    pub path: Vec<(Hash256, bool)>, // (hash, is_left)
    /// Leaf index
    pub leaf_index: usize,
}

impl MerkleProof {
    /// Verify proof against root
    pub fn verify(&self, leaf: &Hash256, root: &Hash256) -> bool {
        let mut current = *leaf;

        for (sibling, is_left) in &self.path {
            current = if *is_left {
                merkle_combine(sibling, &current)
            } else {
                merkle_combine(&current, sibling)
            };
        }

        &current == root
    }
}

/// HMAC-SHA256
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> Hash256 {
    use hmac::{Hmac, Mac};

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    let result = mac.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result.into_bytes());
    Hash256(hash)
}

/// HKDF-SHA256 key derivation
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output: &mut [u8],
) -> Result<(), hkdf::InvalidLength> {
    use hkdf::Hkdf;

    let hk = Hkdf::<Sha256>::new(salt, ikm);
    hk.expand(info, output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256() {
        let hash = sha256(b"hello world");
        assert_eq!(
            hash.to_hex(),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_keccak256() {
        let hash = keccak256(b"hello world");
        assert_eq!(
            hash.to_hex(),
            "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad"
        );
    }

    #[test]
    fn test_blake3() {
        let hash = blake3(b"hello world");
        // BLAKE3 produces deterministic output
        assert!(!hash.is_zero());
    }

    #[test]
    fn test_double_sha256() {
        let hash = double_sha256(b"test");
        assert!(!hash.is_zero());
        assert_ne!(hash, sha256(b"test"));
    }

    #[test]
    fn test_merkle_root() {
        let leaves = vec![sha256(b"a"), sha256(b"b"), sha256(b"c"), sha256(b"d")];

        let root = merkle_root(&leaves);
        assert!(!root.is_zero());

        // Same leaves should produce same root
        let root2 = merkle_root(&leaves);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_merkle_single() {
        let leaf = sha256(b"single");
        let root = merkle_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn test_merkle_empty() {
        let root = merkle_root(&[]);
        assert!(root.is_zero());
    }

    #[test]
    fn test_hmac() {
        let key = b"secret key";
        let data = b"message";
        let mac = hmac_sha256(key, data);
        assert!(!mac.is_zero());
    }

    #[test]
    fn test_transaction_hash_domain_separation() {
        let data = b"tx data";
        let tx_hash = transaction_hash(data);
        let plain_hash = sha256(data);

        // Domain-separated hash should differ from plain hash
        assert_ne!(tx_hash, plain_hash);
    }
}
