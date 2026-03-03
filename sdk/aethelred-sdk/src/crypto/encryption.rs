//! # Authenticated Encryption
//!
//! AES-256-GCM and ChaCha20-Poly1305 encryption.

use super::*;

/// Encrypted data with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Ciphertext
    pub ciphertext: Vec<u8>,
    /// Nonce
    pub nonce: Vec<u8>,
    /// Algorithm used
    pub algorithm: EncryptionAlgorithm,
    /// Additional authenticated data hash (if any)
    pub aad_hash: Option<[u8; 32]>,
}

/// Encryption metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionMetadata {
    /// Algorithm
    pub algorithm: EncryptionAlgorithm,
    /// Nonce
    pub nonce: Vec<u8>,
    /// Key derivation info
    pub key_derivation: KeyDerivationInfo,
    /// AAD hash
    pub aad_hash: [u8; 32],
}

/// Encrypt data with AES-256-GCM
pub fn encrypt_aes_gcm(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedData, CryptoError> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);

    let nonce_bytes = SecureRandom::nonce(12)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Create payload with AAD
    use aes_gcm::aead::Payload;
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let aad_hash = if aad.is_empty() {
        None
    } else {
        Some(super::hash::sha256(aad))
    };

    Ok(EncryptedData {
        ciphertext,
        nonce: nonce_bytes,
        algorithm: EncryptionAlgorithm::Aes256Gcm,
        aad_hash,
    })
}

/// Decrypt data with AES-256-GCM
pub fn decrypt_aes_gcm(
    key: &[u8; 32],
    encrypted: &EncryptedData,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use aes_gcm::{Aes256Gcm, Key, Nonce};
    use aes_gcm::aead::{Aead, KeyInit};

    if encrypted.algorithm != EncryptionAlgorithm::Aes256Gcm {
        return Err(CryptoError::DecryptionFailed(
            "Wrong algorithm".to_string(),
        ));
    }

    // Verify AAD hash if present
    if let Some(expected_hash) = encrypted.aad_hash {
        let actual_hash = super::hash::sha256(aad);
        if expected_hash != actual_hash {
            return Err(CryptoError::DecryptionFailed(
                "AAD mismatch".to_string(),
            ));
        }
    }

    let key = Key::<Aes256Gcm>::from_slice(key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&encrypted.nonce);

    use aes_gcm::aead::Payload;
    let payload = Payload {
        msg: &encrypted.ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Encrypt data with ChaCha20-Poly1305
pub fn encrypt_chacha20(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EncryptedData, CryptoError> {
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use chacha20poly1305::aead::{Aead, KeyInit};

    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);

    let nonce_bytes = SecureRandom::nonce(12)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    use chacha20poly1305::aead::Payload;
    let payload = Payload {
        msg: plaintext,
        aad,
    };

    let ciphertext = cipher
        .encrypt(nonce, payload)
        .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;

    let aad_hash = if aad.is_empty() {
        None
    } else {
        Some(super::hash::sha256(aad))
    };

    Ok(EncryptedData {
        ciphertext,
        nonce: nonce_bytes,
        algorithm: EncryptionAlgorithm::ChaCha20Poly1305,
        aad_hash,
    })
}

/// Decrypt data with ChaCha20-Poly1305
pub fn decrypt_chacha20(
    key: &[u8; 32],
    encrypted: &EncryptedData,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
    use chacha20poly1305::aead::{Aead, KeyInit};

    if encrypted.algorithm != EncryptionAlgorithm::ChaCha20Poly1305 {
        return Err(CryptoError::DecryptionFailed(
            "Wrong algorithm".to_string(),
        ));
    }

    // Verify AAD hash if present
    if let Some(expected_hash) = encrypted.aad_hash {
        let actual_hash = super::hash::sha256(aad);
        if expected_hash != actual_hash {
            return Err(CryptoError::DecryptionFailed(
                "AAD mismatch".to_string(),
            ));
        }
    }

    let key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = Nonce::from_slice(&encrypted.nonce);

    use chacha20poly1305::aead::Payload;
    let payload = Payload {
        msg: &encrypted.ciphertext,
        aad,
    };

    cipher
        .decrypt(nonce, payload)
        .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))
}

/// Encrypt with auto-selected algorithm
pub fn encrypt(
    key: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
    algorithm: EncryptionAlgorithm,
) -> Result<EncryptedData, CryptoError> {
    match algorithm {
        EncryptionAlgorithm::Aes256Gcm | EncryptionAlgorithm::Aes256GcmSiv => {
            encrypt_aes_gcm(key, plaintext, aad)
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => encrypt_chacha20(key, plaintext, aad),
    }
}

/// Decrypt with auto-detected algorithm
pub fn decrypt(
    key: &[u8; 32],
    encrypted: &EncryptedData,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    match encrypted.algorithm {
        EncryptionAlgorithm::Aes256Gcm | EncryptionAlgorithm::Aes256GcmSiv => {
            decrypt_aes_gcm(key, encrypted, aad)
        }
        EncryptionAlgorithm::ChaCha20Poly1305 => decrypt_chacha20(key, encrypted, aad),
    }
}

// ============================================================================
// Envelope Encryption
// ============================================================================

/// Envelope-encrypted data (DEK encrypted with KEK)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvelopeEncrypted {
    /// Encrypted data encryption key
    pub encrypted_dek: EncryptedData,
    /// Encrypted payload
    pub encrypted_data: EncryptedData,
}

/// Encrypt using envelope encryption pattern
pub fn envelope_encrypt(
    kek: &[u8; 32],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EnvelopeEncrypted, CryptoError> {
    // Generate random DEK
    let dek = SecureRandom::random_32()?;

    // Encrypt DEK with KEK
    let encrypted_dek = encrypt_aes_gcm(kek, &dek, b"dek")?;

    // Encrypt data with DEK
    let encrypted_data = encrypt_aes_gcm(&dek, plaintext, aad)?;

    Ok(EnvelopeEncrypted {
        encrypted_dek,
        encrypted_data,
    })
}

/// Decrypt envelope-encrypted data
pub fn envelope_decrypt(
    kek: &[u8; 32],
    envelope: &EnvelopeEncrypted,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Decrypt DEK
    let dek_bytes = decrypt_aes_gcm(kek, &envelope.encrypted_dek, b"dek")?;

    if dek_bytes.len() != 32 {
        return Err(CryptoError::DecryptionFailed(
            "Invalid DEK length".to_string(),
        ));
    }

    let mut dek = [0u8; 32];
    dek.copy_from_slice(&dek_bytes);

    // Decrypt data
    decrypt_aes_gcm(&dek, &envelope.encrypted_data, aad)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_gcm_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"Hello, encrypted world!";
        let aad = b"additional data";

        let encrypted = encrypt_aes_gcm(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_aes_gcm(&key, &encrypted, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_chacha20_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"Hello, encrypted world!";
        let aad = b"additional data";

        let encrypted = encrypt_chacha20(&key, plaintext, aad).unwrap();
        let decrypted = decrypt_chacha20(&key, &encrypted, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key() {
        let key1 = [42u8; 32];
        let key2 = [43u8; 32];
        let plaintext = b"secret";

        let encrypted = encrypt_aes_gcm(&key1, plaintext, &[]).unwrap();
        let result = decrypt_aes_gcm(&key2, &encrypted, &[]);

        assert!(result.is_err());
    }

    #[test]
    fn test_envelope_encryption() {
        let kek = [42u8; 32];
        let plaintext = b"envelope encrypted data";
        let aad = b"aad";

        let envelope = envelope_encrypt(&kek, plaintext, aad).unwrap();
        let decrypted = envelope_decrypt(&kek, &envelope, aad).unwrap();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }
}
