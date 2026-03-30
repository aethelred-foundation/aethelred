#![allow(clippy::panicking_unwrap)]
#![allow(clippy::await_holding_lock)]
#![allow(clippy::only_used_in_recursion)]
#![allow(clippy::if_same_then_else)]
#![allow(clippy::match_like_matches_macro)]
#![allow(unused_doc_comments)]
#![allow(unexpected_cfgs)]
#![allow(ambiguous_glob_reexports)]
#![allow(clippy::upper_case_acronyms)]
#![allow(dead_code)]
#![allow(unused_variables)]
#![allow(clippy::type_complexity)]
#![allow(clippy::result_large_err)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::inconsistent_digit_grouping)]
#![allow(clippy::neg_cmp_op_on_partial_ord)]
#![allow(clippy::should_implement_trait)]
#![allow(clippy::doc_lazy_continuation)]
#![allow(non_camel_case_types)]
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
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 48 bytes, got {}", v.len()))
        })
    }
}

pub mod serde_byte_array_64 {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        data.as_slice().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        let v: Vec<u8> = Vec::deserialize(deserializer)?;
        v.try_into().map_err(|v: Vec<u8>| {
            serde::de::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })
    }
}
