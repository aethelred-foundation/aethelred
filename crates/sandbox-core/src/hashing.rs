//! Hashing primitives — workspace-crypto-first, with a sha2 fallback.
//!
//! With the `real-crypto` feature enabled (default), we use the same
//! `aethelred-core::crypto::sha256` and `merkle_root` primitives that the
//! mainnet protocol uses. This guarantees seal hashes computed by the sandbox
//! are byte-for-byte identical to seal hashes computed by validators.
//!
//! With `real-crypto` disabled, we fall back to `sha2::Sha256` for downstream
//! crates that cannot pull `aethelred-core` (e.g., wasm targets).

use serde::{Deserialize, Serialize};
use std::fmt;

/// 32-byte SHA-256 digest, hex-encoded for display and serialization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sha256Digest(pub [u8; 32]);

impl Sha256Digest {
    /// Construct from raw bytes.
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Hex-encoded representation (lowercase, 64 chars, no `0x` prefix).
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from a 64-char lowercase hex string.
    pub fn from_hex(s: &str) -> Option<Self> {
        let bytes = hex::decode(s).ok()?;
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(Self(out))
    }
}

impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl Serialize for Sha256Digest {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for Sha256Digest {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        use serde::de::Error;
        let s = String::deserialize(de)?;
        Self::from_hex(&s).ok_or_else(|| D::Error::custom("invalid 32-byte hex digest"))
    }
}

/// Hashing helper. The plug-and-play API uses [`Hasher::sha256`] everywhere.
pub struct Hasher;

impl Hasher {
    /// Compute SHA-256 over the input bytes.
    #[cfg(feature = "real-crypto")]
    pub fn sha256(data: &[u8]) -> Sha256Digest {
        let h = aethelred_core::crypto::hash::sha256(data);
        Sha256Digest(h.0)
    }

    /// Compute SHA-256 over the input bytes (sha2 fallback).
    #[cfg(not(feature = "real-crypto"))]
    pub fn sha256(data: &[u8]) -> Sha256Digest {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let out = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&out);
        Sha256Digest(bytes)
    }

    /// Hash a typed serde value via canonical JSON encoding (RFC 8785-style;
    /// uses `serde_json` here — we serialize keys in declaration order which
    /// matches our `#[derive(Serialize)]` derivation, sufficient for our
    /// internal stable types).
    ///
    /// For interop with external producers, prefer [`Hasher::sha256`] over
    /// pre-canonicalised bytes.
    pub fn hash_value<T: Serialize>(value: &T) -> super::SandboxResult<Sha256Digest> {
        let bytes = serde_json::to_vec(value)
            .map_err(|e| super::SandboxError::Crypto(format!("serialize: {e}")))?;
        Ok(Self::sha256(&bytes))
    }

    /// Combine two digests into a Merkle parent. Order-sensitive.
    #[cfg(feature = "real-crypto")]
    pub fn merkle_combine(left: Sha256Digest, right: Sha256Digest) -> Sha256Digest {
        let l = aethelred_core::crypto::hash::Hash256(left.0);
        let r = aethelred_core::crypto::hash::Hash256(right.0);
        let combined = aethelred_core::crypto::hash::merkle_combine(&l, &r);
        Sha256Digest(combined.0)
    }

    /// Combine two digests into a Merkle parent (sha2 fallback).
    #[cfg(not(feature = "real-crypto"))]
    pub fn merkle_combine(left: Sha256Digest, right: Sha256Digest) -> Sha256Digest {
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&left.0);
        combined[32..].copy_from_slice(&right.0);
        Self::sha256(&combined)
    }

    /// Compute a Merkle root over a slice of leaf digests. Empty input
    /// returns the all-zero digest.
    pub fn merkle_root(leaves: &[Sha256Digest]) -> Sha256Digest {
        if leaves.is_empty() {
            return Sha256Digest([0u8; 32]);
        }
        let mut current: Vec<Sha256Digest> = leaves.to_vec();
        while current.len() > 1 {
            let mut next: Vec<Sha256Digest> = Vec::with_capacity((current.len() + 1) / 2);
            for chunk in current.chunks(2) {
                if chunk.len() == 2 {
                    next.push(Self::merkle_combine(chunk[0], chunk[1]));
                } else {
                    // Odd leaf — duplicate (Bitcoin-style).
                    next.push(Self::merkle_combine(chunk[0], chunk[0]));
                }
            }
            current = next;
        }
        current[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vector() {
        // SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
        let d = Hasher::sha256(b"abc");
        assert_eq!(
            d.to_hex(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn merkle_root_empty_is_zero() {
        let r = Hasher::merkle_root(&[]);
        assert_eq!(r.0, [0u8; 32]);
    }

    #[test]
    fn merkle_root_single_is_leaf() {
        let leaf = Hasher::sha256(b"alpha");
        let r = Hasher::merkle_root(&[leaf]);
        assert_eq!(r, leaf);
    }

    #[test]
    fn merkle_root_pair_combines() {
        let a = Hasher::sha256(b"a");
        let b = Hasher::sha256(b"b");
        let combined = Hasher::merkle_combine(a, b);
        let root = Hasher::merkle_root(&[a, b]);
        assert_eq!(combined, root);
    }

    #[test]
    fn digest_hex_roundtrip() {
        let d = Hasher::sha256(b"roundtrip");
        let s = d.to_hex();
        let d2 = Sha256Digest::from_hex(&s).unwrap();
        assert_eq!(d, d2);
    }
}
