//! Cryptographic Pre-Compiles
//!
//! Standard and post-quantum cryptographic precompiles.

use super::{
    addresses, gas_costs, word_gas_cost, ExecutionResult, Precompile, PrecompileError,
    PrecompileResult,
};
use k256::ecdsa::{RecoveryId, Signature as K256Signature, VerifyingKey};
use pqcrypto_dilithium::{dilithium3, dilithium5};
use pqcrypto_kyber::{kyber1024, kyber768};
use pqcrypto_traits::kem::{
    Ciphertext as PQCiphertext, SecretKey as PQSecretKey, SharedSecret as PQSharedSecret,
};
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as PQSigPublicKey};
use sha2::{Digest, Sha256};
use sha3::Keccak256;

/// SHA-256 precompile
pub struct Sha256Precompile;

impl Precompile for Sha256Precompile {
    fn address(&self) -> u64 {
        addresses::SHA256
    }

    fn name(&self) -> &'static str {
        "SHA256"
    }

    fn gas_cost(&self, input: &[u8]) -> u64 {
        word_gas_cost(
            gas_costs::SHA256_BASE,
            gas_costs::SHA256_PER_WORD,
            input.len(),
        )
    }

    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult<ExecutionResult> {
        let gas = self.gas_cost(input);
        if gas > gas_limit {
            return Err(PrecompileError::OutOfGas {
                required: gas,
                available: gas_limit,
            });
        }

        let hash = Sha256::digest(input);
        Ok(ExecutionResult::success(hash.to_vec(), gas))
    }
}

/// Identity (data copy) precompile
pub struct IdentityPrecompile;

impl Precompile for IdentityPrecompile {
    fn address(&self) -> u64 {
        addresses::IDENTITY
    }

    fn name(&self) -> &'static str {
        "IDENTITY"
    }

    fn gas_cost(&self, input: &[u8]) -> u64 {
        word_gas_cost(
            gas_costs::IDENTITY_BASE,
            gas_costs::IDENTITY_PER_WORD,
            input.len(),
        )
    }

    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult<ExecutionResult> {
        let gas = self.gas_cost(input);
        if gas > gas_limit {
            return Err(PrecompileError::OutOfGas {
                required: gas,
                available: gas_limit,
            });
        }

        Ok(ExecutionResult::success(input.to_vec(), gas))
    }
}

/// ECDSA recover precompile — secp256k1 public key recovery from signature.
///
/// Implements EIP-like ecrecover: given a message hash and (v, r, s) signature,
/// recovers the signer's Ethereum-style address (Keccak256 of uncompressed pubkey).
pub struct EcdsaRecoverPrecompile;

impl Precompile for EcdsaRecoverPrecompile {
    fn address(&self) -> u64 {
        addresses::ECDSA_RECOVER
    }

    fn name(&self) -> &'static str {
        "ECDSA_RECOVER"
    }

    fn gas_cost(&self, _input: &[u8]) -> u64 {
        gas_costs::ECDSA_RECOVER
    }

    fn min_input_length(&self) -> usize {
        128 // hash (32) + v (32) + r (32) + s (32)
    }

    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult<ExecutionResult> {
        let gas = self.gas_cost(input);
        if gas > gas_limit {
            return Err(PrecompileError::OutOfGas {
                required: gas,
                available: gas_limit,
            });
        }

        if input.len() < 128 {
            return Ok(ExecutionResult::failure(gas));
        }

        // Parse input: hash (32) | v (32) | r (32) | s (32)
        let hash = &input[0..32];
        let v = &input[32..64];
        let r = &input[64..96];
        let s = &input[96..128];

        // Extract recovery id from v (padded to 32 bytes, actual value in last byte)
        let v_byte = v[31];
        let rec_id = match v_byte {
            27 | 28 => v_byte - 27,
            0 | 1 => v_byte,
            _ => return Ok(ExecutionResult::failure(gas)),
        };

        let recovery_id = match RecoveryId::try_from(rec_id) {
            Ok(id) => id,
            Err(_) => return Ok(ExecutionResult::failure(gas)),
        };

        // Construct the 64-byte signature (r || s)
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(r);
        sig_bytes[32..].copy_from_slice(s);

        let signature = match K256Signature::try_from(sig_bytes.as_slice()) {
            Ok(sig) => sig,
            Err(_) => return Ok(ExecutionResult::failure(gas)),
        };

        // Recover the public key from the prehashed message
        let recovered_key = match VerifyingKey::recover_from_prehash(hash, &signature, recovery_id)
        {
            Ok(key) => key,
            Err(_) => return Ok(ExecutionResult::failure(gas)),
        };

        // Derive Ethereum-style address: Keccak256 of uncompressed pubkey (sans 0x04 prefix)
        let uncompressed = recovered_key.to_encoded_point(false);
        let pubkey_bytes = &uncompressed.as_bytes()[1..]; // skip 0x04 prefix
        let address_hash = Keccak256::digest(pubkey_bytes);

        // Return 32-byte output with address in the last 20 bytes (left-padded with zeros)
        let mut output = vec![0u8; 32];
        output[12..32].copy_from_slice(&address_hash[12..32]);

        Ok(ExecutionResult::success(output, gas))
    }
}

/// Dilithium3 signature verification precompile
pub struct DilithiumVerifyPrecompile {
    /// Security level
    level: DilithiumLevel,
}

#[derive(Debug, Clone, Copy)]
pub enum DilithiumLevel {
    Level3,
    Level5,
}

impl DilithiumVerifyPrecompile {
    /// Create Dilithium3 verifier
    pub fn new() -> Self {
        Self {
            level: DilithiumLevel::Level3,
        }
    }

    /// Create Dilithium5 verifier
    pub fn level5() -> Self {
        Self {
            level: DilithiumLevel::Level5,
        }
    }

    /// Get public key size for level
    fn public_key_size(&self) -> usize {
        match self.level {
            DilithiumLevel::Level3 => 1952,
            DilithiumLevel::Level5 => 2592,
        }
    }

    /// Get signature size for level
    fn signature_size(&self) -> usize {
        match self.level {
            DilithiumLevel::Level3 => 3293,
            DilithiumLevel::Level5 => 4595,
        }
    }
}

impl Default for DilithiumVerifyPrecompile {
    fn default() -> Self {
        Self::new()
    }
}

impl Precompile for DilithiumVerifyPrecompile {
    fn address(&self) -> u64 {
        match self.level {
            DilithiumLevel::Level3 => addresses::DILITHIUM_VERIFY,
            DilithiumLevel::Level5 => addresses::DILITHIUM5_VERIFY,
        }
    }

    fn name(&self) -> &'static str {
        match self.level {
            DilithiumLevel::Level3 => "DILITHIUM3_VERIFY",
            DilithiumLevel::Level5 => "DILITHIUM5_VERIFY",
        }
    }

    fn gas_cost(&self, _input: &[u8]) -> u64 {
        match self.level {
            DilithiumLevel::Level3 => gas_costs::DILITHIUM3_VERIFY,
            DilithiumLevel::Level5 => gas_costs::DILITHIUM5_VERIFY,
        }
    }

    fn min_input_length(&self) -> usize {
        // message_len (4) + message + public_key + signature
        4 + self.public_key_size() + self.signature_size()
    }

    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult<ExecutionResult> {
        let gas = self.gas_cost(input);
        if gas > gas_limit {
            return Err(PrecompileError::OutOfGas {
                required: gas,
                available: gas_limit,
            });
        }

        // Input format: [msg_len:4][message:msg_len][public_key][signature]
        if input.len() < 4 {
            return Ok(ExecutionResult::failure(gas));
        }

        let msg_len = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;

        let pk_start = 4 + msg_len;
        let pk_end = pk_start + self.public_key_size();
        let sig_start = pk_end;
        let sig_end = sig_start + self.signature_size();

        if input.len() < sig_end {
            return Ok(ExecutionResult::failure(gas));
        }

        let message = &input[4..pk_start];
        let public_key_bytes = &input[pk_start..pk_end];
        let signature_bytes = &input[sig_start..sig_end];

        // Perform real Dilithium verification using pqcrypto-dilithium
        let valid = match self.level {
            DilithiumLevel::Level3 => {
                let pk = match dilithium3::PublicKey::from_bytes(public_key_bytes) {
                    Ok(pk) => pk,
                    Err(_) => return Ok(ExecutionResult::failure(gas)),
                };
                let sig = match dilithium3::DetachedSignature::from_bytes(signature_bytes) {
                    Ok(sig) => sig,
                    Err(_) => return Ok(ExecutionResult::failure(gas)),
                };
                dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            DilithiumLevel::Level5 => {
                let pk = match dilithium5::PublicKey::from_bytes(public_key_bytes) {
                    Ok(pk) => pk,
                    Err(_) => return Ok(ExecutionResult::failure(gas)),
                };
                let sig = match dilithium5::DetachedSignature::from_bytes(signature_bytes) {
                    Ok(sig) => sig,
                    Err(_) => return Ok(ExecutionResult::failure(gas)),
                };
                dilithium5::verify_detached_signature(&sig, message, &pk).is_ok()
            }
        };

        // Return 1 for valid, 0 for invalid (32-byte padded)
        let mut output = vec![0u8; 32];
        if valid {
            output[31] = 1;
        }

        Ok(ExecutionResult::success(output, gas))
    }
}

/// Kyber768 decapsulation precompile
pub struct KyberDecapsPrecompile {
    level: KyberLevel,
}

#[derive(Debug, Clone, Copy)]
pub enum KyberLevel {
    Kyber768,
    Kyber1024,
}

impl KyberDecapsPrecompile {
    /// Create Kyber768 decaps
    pub fn new() -> Self {
        Self {
            level: KyberLevel::Kyber768,
        }
    }

    /// Create Kyber1024 decaps
    pub fn kyber1024() -> Self {
        Self {
            level: KyberLevel::Kyber1024,
        }
    }

    fn secret_key_size(&self) -> usize {
        match self.level {
            KyberLevel::Kyber768 => 2400,
            KyberLevel::Kyber1024 => 3168,
        }
    }

    fn ciphertext_size(&self) -> usize {
        match self.level {
            KyberLevel::Kyber768 => 1088,
            KyberLevel::Kyber1024 => 1568,
        }
    }
}

impl Default for KyberDecapsPrecompile {
    fn default() -> Self {
        Self::new()
    }
}

impl Precompile for KyberDecapsPrecompile {
    fn address(&self) -> u64 {
        match self.level {
            KyberLevel::Kyber768 => addresses::KYBER_DECAPS,
            KyberLevel::Kyber1024 => addresses::KYBER1024_DECAPS,
        }
    }

    fn name(&self) -> &'static str {
        match self.level {
            KyberLevel::Kyber768 => "KYBER768_DECAPS",
            KyberLevel::Kyber1024 => "KYBER1024_DECAPS",
        }
    }

    fn gas_cost(&self, _input: &[u8]) -> u64 {
        match self.level {
            KyberLevel::Kyber768 => gas_costs::KYBER768_DECAPS,
            KyberLevel::Kyber1024 => gas_costs::KYBER1024_DECAPS,
        }
    }

    fn min_input_length(&self) -> usize {
        self.secret_key_size() + self.ciphertext_size()
    }

    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult<ExecutionResult> {
        let gas = self.gas_cost(input);
        if gas > gas_limit {
            return Err(PrecompileError::OutOfGas {
                required: gas,
                available: gas_limit,
            });
        }

        let min_len = self.min_input_length();
        if input.len() < min_len {
            return Err(PrecompileError::InvalidInputLength {
                expected: min_len,
                actual: input.len(),
            });
        }

        // Input format: [secret_key][ciphertext]
        let sk_end = self.secret_key_size();
        let secret_key_bytes = &input[0..sk_end];
        let ciphertext_bytes = &input[sk_end..sk_end + self.ciphertext_size()];

        // Perform real Kyber decapsulation using pqcrypto-kyber
        let shared_secret = match self.level {
            KyberLevel::Kyber768 => {
                let ct = kyber768::Ciphertext::from_bytes(ciphertext_bytes).map_err(|_| {
                    PrecompileError::InvalidInputFormat("Invalid Kyber768 ciphertext".into())
                })?;
                let sk = kyber768::SecretKey::from_bytes(secret_key_bytes).map_err(|_| {
                    PrecompileError::InvalidInputFormat("Invalid Kyber768 secret key".into())
                })?;
                let ss = kyber768::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
            KyberLevel::Kyber1024 => {
                let ct = kyber1024::Ciphertext::from_bytes(ciphertext_bytes).map_err(|_| {
                    PrecompileError::InvalidInputFormat("Invalid Kyber1024 ciphertext".into())
                })?;
                let sk = kyber1024::SecretKey::from_bytes(secret_key_bytes).map_err(|_| {
                    PrecompileError::InvalidInputFormat("Invalid Kyber1024 secret key".into())
                })?;
                let ss = kyber1024::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            }
        };

        Ok(ExecutionResult::success(shared_secret, gas))
    }
}

/// Hybrid (ECDSA + Dilithium3) verification precompile
pub struct HybridVerifyPrecompile;

impl HybridVerifyPrecompile {
    pub fn new() -> Self {
        Self
    }

    /// Public key size (ECDSA compressed + separator + Dilithium3)
    fn public_key_size(&self) -> usize {
        1 + 33 + 1 + 1952 // marker + ecdsa + sep + dilithium
    }

    /// Signature size (ECDSA + separator + Dilithium3)
    fn signature_size(&self) -> usize {
        1 + 64 + 1 + 3293 // marker + ecdsa + sep + dilithium
    }
}

impl Default for HybridVerifyPrecompile {
    fn default() -> Self {
        Self::new()
    }
}

impl Precompile for HybridVerifyPrecompile {
    fn address(&self) -> u64 {
        addresses::HYBRID_VERIFY
    }

    fn name(&self) -> &'static str {
        "HYBRID_VERIFY"
    }

    fn gas_cost(&self, _input: &[u8]) -> u64 {
        gas_costs::HYBRID_VERIFY
    }

    fn min_input_length(&self) -> usize {
        // threat_level (1) + msg_len (4) + message + public_key + signature
        1 + 4 + self.public_key_size() + self.signature_size()
    }

    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult<ExecutionResult> {
        let gas = self.gas_cost(input);
        if gas > gas_limit {
            return Err(PrecompileError::OutOfGas {
                required: gas,
                available: gas_limit,
            });
        }

        if input.len() < 5 {
            return Ok(ExecutionResult::failure(gas));
        }

        // Input format: [threat_level:1][msg_len:4][message:msg_len][public_key][signature]
        let threat_level = input[0];
        let msg_len = u32::from_le_bytes([input[1], input[2], input[3], input[4]]) as usize;

        let msg_start = 5;
        let msg_end = msg_start + msg_len;
        let pk_start = msg_end;
        let pk_end = pk_start + self.public_key_size();
        let sig_start = pk_end;
        let sig_end = sig_start + self.signature_size();

        if input.len() < sig_end {
            return Ok(ExecutionResult::failure(gas));
        }

        let message = &input[msg_start..msg_end];
        let public_key = &input[pk_start..pk_end];
        let signature = &input[sig_start..sig_end];

        // Parse hybrid public key: [marker(1)][ecdsa_compressed(33)][sep(1)][dilithium(1952)]
        let ecdsa_pk_bytes = &public_key[1..34];
        let dilithium_pk_bytes = &public_key[35..35 + 1952];

        // Parse hybrid signature: [marker(1)][ecdsa(64)][sep(1)][dilithium(3293)]
        let ecdsa_sig_bytes = &signature[1..65];
        let dilithium_sig_bytes = &signature[66..66 + 3293];

        // 1. Verify ECDSA signature using k256
        let ecdsa_valid = (|| -> bool {
            use k256::ecdsa::signature::Verifier;

            let vk = match k256::ecdsa::VerifyingKey::from_sec1_bytes(ecdsa_pk_bytes) {
                Ok(vk) => vk,
                Err(_) => return false,
            };
            let sig = match K256Signature::try_from(ecdsa_sig_bytes) {
                Ok(sig) => sig,
                Err(_) => return false,
            };
            // Hash message with SHA-256 for ECDSA verification
            let msg_hash = Sha256::digest(message);
            vk.verify(&msg_hash, &sig).is_ok()
        })();

        // 2. Verify Dilithium3 signature using pqcrypto-dilithium
        let dilithium_valid = (|| -> bool {
            let pk = match dilithium3::PublicKey::from_bytes(dilithium_pk_bytes) {
                Ok(pk) => pk,
                Err(_) => return false,
            };
            let sig = match dilithium3::DetachedSignature::from_bytes(dilithium_sig_bytes) {
                Ok(sig) => sig,
                Err(_) => return false,
            };
            dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
        })();

        // Both must be valid for the hybrid signature to pass
        let valid = ecdsa_valid && dilithium_valid;

        // Return result: [valid:1][threat_level_used:1][padding:30]
        let mut output = vec![0u8; 32];
        if valid {
            output[31] = 1;
        }
        output[30] = threat_level;

        Ok(ExecutionResult::success(output, gas))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha256_precompile() {
        let precompile = Sha256Precompile;
        let input = b"hello world";
        let result = precompile.execute(input, 1_000_000).unwrap();

        assert!(result.success);
        assert_eq!(result.output.len(), 32);

        // Verify hash is correct
        let expected = Sha256::digest(input);
        assert_eq!(result.output, expected[..]);
    }

    #[test]
    fn test_identity_precompile() {
        let precompile = IdentityPrecompile;
        let input = b"test data";
        let result = precompile.execute(input, 1_000_000).unwrap();

        assert!(result.success);
        assert_eq!(result.output, input);
    }

    #[test]
    fn test_ecdsa_recover_short_input() {
        let precompile = EcdsaRecoverPrecompile;
        let input = vec![0u8; 64]; // Too short
        let result = precompile.execute(&input, 1_000_000).unwrap();

        assert!(!result.success);
    }

    #[test]
    fn test_dilithium_verify() {
        let precompile = DilithiumVerifyPrecompile::new();

        // Create valid-format input
        let msg = b"test message";
        let msg_len = (msg.len() as u32).to_le_bytes();

        let mut input = Vec::new();
        input.extend_from_slice(&msg_len);
        input.extend_from_slice(msg);
        input.extend_from_slice(&vec![0u8; 1952]); // public key
        input.extend_from_slice(&vec![0u8; 3293]); // signature

        let result = precompile.execute(&input, 1_000_000).unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_hybrid_verify() {
        let precompile = HybridVerifyPrecompile::new();

        // Create valid-format input
        let msg = b"test";
        let msg_len = (msg.len() as u32).to_le_bytes();

        let mut input = Vec::new();
        input.push(0); // threat level
        input.extend_from_slice(&msg_len);
        input.extend_from_slice(msg);
        input.extend_from_slice(&vec![0u8; 1 + 33 + 1 + 1952]); // public key
        input.extend_from_slice(&vec![0u8; 1 + 64 + 1 + 3293]); // signature

        let result = precompile.execute(&input, 1_000_000).unwrap();
        assert!(result.success);
        // Zeroed signature material should parse but fail verification.
        assert_eq!(result.output[31], 0);
    }

    #[test]
    fn test_gas_costs() {
        let sha256 = Sha256Precompile;
        assert_eq!(sha256.gas_cost(&[]), gas_costs::SHA256_BASE);
        assert_eq!(
            sha256.gas_cost(&[0; 32]),
            gas_costs::SHA256_BASE + gas_costs::SHA256_PER_WORD
        );

        let dilithium = DilithiumVerifyPrecompile::new();
        assert_eq!(dilithium.gas_cost(&[]), gas_costs::DILITHIUM3_VERIFY);
    }
}
