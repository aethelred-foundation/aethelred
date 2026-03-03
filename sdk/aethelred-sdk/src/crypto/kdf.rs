//! # Key Derivation Functions
//!
//! Secure key derivation for various use cases.

use super::*;

/// Key derivation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyDerivationInfo {
    /// Algorithm used
    pub algorithm: KdfAlgorithm,
    /// Salt
    pub salt: Vec<u8>,
    /// Context info
    pub info: String,
    /// Iterations (for PBKDF2/Argon2)
    pub iterations: Option<u32>,
}

/// Derive a key using HKDF-SHA256
pub fn hkdf_sha256(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expand failed".to_string()))?;

    Ok(okm)
}

/// Derive a key using HKDF-SHA384
pub fn hkdf_sha384(
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    use hkdf::Hkdf;
    use sha2::Sha384;

    let hk = Hkdf::<Sha384>::new(Some(salt), ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm)
        .map_err(|_| CryptoError::KeyDerivationFailed("HKDF expand failed".to_string()))?;

    Ok(okm)
}

/// Derive a key from password using Argon2id
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    use argon2::{Argon2, Algorithm, Version, Params};

    let params = Params::new(65536, 3, 4, Some(output_len))
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| CryptoError::KeyDerivationFailed(e.to_string()))?;

    Ok(output)
}

/// Derive a key using PBKDF2-SHA256
pub fn pbkdf2_sha256(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    use pbkdf2::pbkdf2_hmac;
    use sha2::Sha256;

    let mut output = vec![0u8; output_len];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut output);

    Ok(output)
}

/// Derive key with specified algorithm
pub fn derive_key(
    secret: &[u8],
    info: &KeyDerivationInfo,
    output_len: usize,
) -> Result<Vec<u8>, CryptoError> {
    match info.algorithm {
        KdfAlgorithm::HkdfSha256 => {
            hkdf_sha256(secret, &info.salt, info.info.as_bytes(), output_len)
        }
        KdfAlgorithm::HkdfSha384 => {
            hkdf_sha384(secret, &info.salt, info.info.as_bytes(), output_len)
        }
        KdfAlgorithm::Argon2id => argon2id(secret, &info.salt, output_len),
        KdfAlgorithm::Pbkdf2Sha256 => {
            let iterations = info.iterations.unwrap_or(100_000);
            pbkdf2_sha256(secret, &info.salt, iterations, output_len)
        }
    }
}

/// Derive an encryption key from a master secret
pub fn derive_encryption_key(
    master_secret: &[u8; 32],
    purpose: &str,
    context: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let info = format!("aethelred:encryption:{}", purpose);
    let mut combined_info = Vec::new();
    combined_info.extend_from_slice(info.as_bytes());
    combined_info.extend_from_slice(context);

    let key = hkdf_sha256(master_secret, &[], &combined_info, 32)?;

    let mut result = [0u8; 32];
    result.copy_from_slice(&key);
    Ok(result)
}

/// Derive a signing key from a master secret
pub fn derive_signing_key(
    master_secret: &[u8; 32],
    purpose: &str,
    context: &[u8],
) -> Result<[u8; 32], CryptoError> {
    let info = format!("aethelred:signing:{}", purpose);
    let mut combined_info = Vec::new();
    combined_info.extend_from_slice(info.as_bytes());
    combined_info.extend_from_slice(context);

    let key = hkdf_sha256(master_secret, &[], &combined_info, 32)?;

    let mut result = [0u8; 32];
    result.copy_from_slice(&key);
    Ok(result)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_sha256() {
        let ikm = b"secret";
        let salt = b"salt";
        let info = b"context";

        let key = hkdf_sha256(ikm, salt, info, 32).unwrap();
        assert_eq!(key.len(), 32);

        // Deterministic
        let key2 = hkdf_sha256(ikm, salt, info, 32).unwrap();
        assert_eq!(key, key2);
    }

    #[test]
    fn test_derive_encryption_key() {
        let master = [42u8; 32];

        let key = derive_encryption_key(&master, "data", b"context1").unwrap();
        assert_eq!(key.len(), 32);

        // Different context = different key
        let key2 = derive_encryption_key(&master, "data", b"context2").unwrap();
        assert_ne!(key, key2);
    }
}
