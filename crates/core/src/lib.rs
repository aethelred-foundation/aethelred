//! Aethelred core crate
//!
//! Minimal module wiring for shared types and cryptography primitives.

pub mod crypto;
pub mod pillars;
pub mod transport;
pub mod types;

#[cfg(kani)]
mod kani_proofs;

/// Serde helpers for serializing/deserializing byte arrays larger than 32 elements.
/// Needed because the vendored serde only supports arrays up to 32 elements.
pub mod serde_byte_array_48 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 48], D::Error> {
        let v: Vec<u8> = Vec::deserialize(deserializer)?;
        v.try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::custom(format!("expected 48 bytes, got {}", v.len())))
    }
}

pub mod serde_byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(deserializer)?;
        v.try_into()
            .map_err(|v: Vec<u8>| serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len())))
    }
}
