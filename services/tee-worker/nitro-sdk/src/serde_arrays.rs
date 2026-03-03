//! Serde helpers for fixed-size byte arrays larger than 32 bytes.
//!
//! The vendored serde configuration in this workspace does not provide blanket
//! Serialize/Deserialize impls for arrays larger than 32 elements. These
//! modules provide explicit field-level serializers for the SDK types that use
//! `[u8; 48]`, `[u8; 64]`, and fixed arrays of those values.

#![allow(dead_code)]

use serde::de::Error as _;
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serializer};

fn serialize_bytes<const N: usize, S>(value: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_bytes(value)
}

fn deserialize_bytes<const N: usize, D>(deserializer: D) -> Result<[u8; N], D::Error>
where
    D: Deserializer<'static>,
{
    let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
    if bytes.len() != N {
        return Err(D::Error::custom(format!(
            "expected {N} bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub mod u8_48 {
    use super::*;
    pub fn serialize<S>(value: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bytes(value, serializer)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        if bytes.len() != 48 {
            return Err(D::Error::custom(format!(
                "expected 48 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

pub mod u8_64 {
    use super::*;
    pub fn serialize<S>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serialize_bytes(value, serializer)
    }
    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = serde_bytes::ByteBuf::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(D::Error::custom(format!(
                "expected 64 bytes, got {}",
                bytes.len()
            )));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&bytes);
        Ok(out)
    }
}

pub mod u8_48x4 {
    use super::*;

    pub fn serialize<S>(value: &[[u8; 48]; 4], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(4))?;
        for row in value {
            seq.serialize_element(serde_bytes::Bytes::new(row))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[[u8; 48]; 4], D::Error>
    where
        D: Deserializer<'de>,
    {
        let rows: Vec<serde_bytes::ByteBuf> = Vec::deserialize(deserializer)?;
        if rows.len() != 4 {
            return Err(D::Error::custom(format!(
                "expected 4 rows, got {}",
                rows.len()
            )));
        }
        let mut out = [[0u8; 48]; 4];
        for (idx, row) in rows.into_iter().enumerate() {
            if row.len() != 48 {
                return Err(D::Error::custom(format!(
                    "expected row size 48, got {} at index {idx}",
                    row.len()
                )));
            }
            out[idx].copy_from_slice(&row);
        }
        Ok(out)
    }
}

pub mod u8_64x4 {
    use super::*;

    pub fn serialize<S>(value: &[[u8; 64]; 4], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(4))?;
        for row in value {
            seq.serialize_element(serde_bytes::Bytes::new(row))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[[u8; 64]; 4], D::Error>
    where
        D: Deserializer<'de>,
    {
        let rows: Vec<serde_bytes::ByteBuf> = Vec::deserialize(deserializer)?;
        if rows.len() != 4 {
            return Err(D::Error::custom(format!(
                "expected 4 rows, got {}",
                rows.len()
            )));
        }
        let mut out = [[0u8; 64]; 4];
        for (idx, row) in rows.into_iter().enumerate() {
            if row.len() != 64 {
                return Err(D::Error::custom(format!(
                    "expected row size 64, got {} at index {idx}",
                    row.len()
                )));
            }
            out[idx].copy_from_slice(&row);
        }
        Ok(out)
    }
}
