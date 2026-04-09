//! Integration tests for the aethelred-core crate.
//!
//! Tests cover type construction, cryptographic hashing, and serde
//! byte-array helpers.

// ---------------------------------------------------------------------------
// Serde byte array helpers
// ---------------------------------------------------------------------------

#[test]
fn test_serde_byte_array_48_roundtrip() {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Wrapper {
        #[serde(with = "aethelred_core::serde_byte_array_48")]
        data: [u8; 48],
    }

    let original = Wrapper { data: [0xAB; 48] };
    let json = serde_json::to_string(&original).expect("serialize");
    let decoded: Wrapper = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, decoded);
}

#[test]
fn test_serde_byte_array_64_roundtrip() {
    #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
    struct Wrapper {
        #[serde(with = "aethelred_core::serde_byte_array_64")]
        data: [u8; 64],
    }

    let original = Wrapper { data: [0xCD; 64] };
    let json = serde_json::to_string(&original).expect("serialize");
    let decoded: Wrapper = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(original, decoded);
}

#[test]
fn test_serde_byte_array_48_wrong_length_errors() {
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(with = "aethelred_core::serde_byte_array_48")]
        #[allow(dead_code)]
        data: [u8; 48],
    }

    // Array of 32 bytes instead of 48
    let bad_json = r#"{"data":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#;
    let result = serde_json::from_str::<Wrapper>(bad_json);
    assert!(result.is_err());
}

#[test]
fn test_serde_byte_array_64_wrong_length_errors() {
    #[derive(serde::Deserialize)]
    struct Wrapper {
        #[serde(with = "aethelred_core::serde_byte_array_64")]
        #[allow(dead_code)]
        data: [u8; 64],
    }

    // Array of 32 bytes instead of 64
    let bad_json = r#"{"data":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}"#;
    let result = serde_json::from_str::<Wrapper>(bad_json);
    assert!(result.is_err());
}

// ---------------------------------------------------------------------------
// Module accessibility
// ---------------------------------------------------------------------------

#[test]
fn test_crypto_module_accessible() {
    // Verify the crypto module compiles and is reachable.
    let _ = std::any::type_name::<aethelred_core::crypto::hash::Sha256Hasher>();
}

#[test]
fn test_types_module_accessible() {
    let _ = std::mem::size_of::<aethelred_core::types::address::Address>();
}

#[test]
fn test_pillars_module_accessible() {
    // Verify pillar sub-modules compile and are reachable through the
    // public module path.
    let _ = std::any::type_name::<fn()>();
    // The pillars module exists; specific types vary so just confirm the
    // module path resolves at compile time.
    mod _check {
        #[allow(unused_imports)]
        use aethelred_core::pillars;
    }
}
