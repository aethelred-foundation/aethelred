//! Host Functions
//!
//! Host functions exposed to WASM modules for interacting with the Aethelred runtime.

use crate::gas::SharedGasMeter;
use crate::precompiles::PrecompileRegistry;
use k256::ecdsa::signature::Verifier as _;
use k256::ecdsa::{Signature as K256Signature, VerifyingKey};
use pqcrypto_dilithium::{dilithium2, dilithium3, dilithium5};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use std::sync::Arc;

/// Host environment context
pub struct HostContext {
    /// Gas meter
    pub gas_meter: SharedGasMeter,
    /// Precompile registry
    pub precompiles: Arc<PrecompileRegistry>,
    /// Block number
    pub block_number: u64,
    /// Block timestamp
    pub block_timestamp: u64,
    /// Chain ID
    pub chain_id: u64,
    /// Caller address
    pub caller: Option<[u8; 32]>,
    /// Contract address
    pub contract: Option<[u8; 32]>,
}

impl HostContext {
    /// Create new context
    pub fn new(gas_meter: SharedGasMeter, precompiles: Arc<PrecompileRegistry>) -> Self {
        Self {
            gas_meter,
            precompiles,
            block_number: 0,
            block_timestamp: 0,
            chain_id: 1,
            caller: None,
            contract: None,
        }
    }

    /// Set block info
    pub fn with_block_info(mut self, number: u64, timestamp: u64, chain_id: u64) -> Self {
        self.block_number = number;
        self.block_timestamp = timestamp;
        self.chain_id = chain_id;
        self
    }

    /// Set addresses
    pub fn with_addresses(mut self, caller: [u8; 32], contract: [u8; 32]) -> Self {
        self.caller = Some(caller);
        self.contract = Some(contract);
        self
    }
}

/// Host function result
#[derive(Debug, Clone)]
pub enum HostResult {
    /// Success with return data
    Success(Vec<u8>),
    /// Error with code and message
    Error(u32, String),
}

impl HostResult {
    /// Check if successful
    pub fn is_success(&self) -> bool {
        matches!(self, HostResult::Success(_))
    }

    /// Get success data
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            HostResult::Success(data) => Some(data),
            HostResult::Error(_, _) => None,
        }
    }

    /// Get error code
    pub fn error_code(&self) -> Option<u32> {
        match self {
            HostResult::Success(_) => None,
            HostResult::Error(code, _) => Some(*code),
        }
    }
}

/// Host function namespace
pub struct HostFunctions;

impl HostFunctions {
    // =========================================================================
    // CRYPTOGRAPHY
    // =========================================================================

    /// Verify ECDSA secp256k1 signature
    pub fn verify_ecdsa(
        _ctx: &HostContext,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> HostResult {
        if signature.len() != 64 {
            return HostResult::Error(1, "Invalid signature length".into());
        }
        if public_key.len() != 33 && public_key.len() != 65 {
            return HostResult::Error(2, "Invalid public key length".into());
        }

        let signature = match K256Signature::from_slice(signature) {
            Ok(sig) => sig,
            Err(_) => return HostResult::Error(3, "Invalid ECDSA signature encoding".into()),
        };
        let verifying_key = match VerifyingKey::from_sec1_bytes(public_key) {
            Ok(pk) => pk,
            Err(_) => return HostResult::Error(4, "Invalid ECDSA public key".into()),
        };

        if verifying_key.verify(message, &signature).is_ok() {
            HostResult::Success(vec![1])
        } else {
            HostResult::Error(5, "ECDSA signature verification failed".into())
        }
    }

    /// Verify Dilithium3 signature
    pub fn verify_dilithium(
        _ctx: &HostContext,
        message: &[u8],
        signature: &[u8],
        public_key: &[u8],
    ) -> HostResult {
        let verified = match (public_key.len(), signature.len()) {
            (pk, sig)
                if pk == dilithium2::public_key_bytes() && sig == dilithium2::signature_bytes() =>
            {
                let pk = match dilithium2::PublicKey::from_bytes(public_key) {
                    Ok(pk) => pk,
                    Err(_) => return HostResult::Error(2, "Invalid Dilithium2 public key".into()),
                };
                let sig = match dilithium2::DetachedSignature::from_bytes(signature) {
                    Ok(sig) => sig,
                    Err(_) => return HostResult::Error(3, "Invalid Dilithium2 signature".into()),
                };
                dilithium2::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            (pk, sig)
                if pk == dilithium3::public_key_bytes() && sig == dilithium3::signature_bytes() =>
            {
                let pk = match dilithium3::PublicKey::from_bytes(public_key) {
                    Ok(pk) => pk,
                    Err(_) => return HostResult::Error(2, "Invalid Dilithium3 public key".into()),
                };
                let sig = match dilithium3::DetachedSignature::from_bytes(signature) {
                    Ok(sig) => sig,
                    Err(_) => return HostResult::Error(3, "Invalid Dilithium3 signature".into()),
                };
                dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            (pk, sig)
                if pk == dilithium5::public_key_bytes() && sig == dilithium5::signature_bytes() =>
            {
                let pk = match dilithium5::PublicKey::from_bytes(public_key) {
                    Ok(pk) => pk,
                    Err(_) => return HostResult::Error(2, "Invalid Dilithium5 public key".into()),
                };
                let sig = match dilithium5::DetachedSignature::from_bytes(signature) {
                    Ok(sig) => sig,
                    Err(_) => return HostResult::Error(3, "Invalid Dilithium5 signature".into()),
                };
                dilithium5::verify_detached_signature(&sig, message, &pk).is_ok()
            }
            _ => {
                return HostResult::Error(
                    1,
                    format!(
                        "Unsupported Dilithium key/signature sizes: pk={} sig={}",
                        public_key.len(),
                        signature.len()
                    ),
                )
            }
        };

        if verified {
            HostResult::Success(vec![1])
        } else {
            HostResult::Error(4, "Dilithium signature verification failed".into())
        }
    }

    /// Verify hybrid (ECDSA + Dilithium) signature
    pub fn verify_hybrid(
        ctx: &HostContext,
        message: &[u8],
        classical_sig: &[u8],
        quantum_sig: &[u8],
        classical_pk: &[u8],
        quantum_pk: &[u8],
    ) -> HostResult {
        // Verify both signatures
        let classical = Self::verify_ecdsa(ctx, message, classical_sig, classical_pk);
        if !classical.is_success() {
            return HostResult::Error(1, "Classical signature verification failed".into());
        }

        let quantum = Self::verify_dilithium(ctx, message, quantum_sig, quantum_pk);
        if !quantum.is_success() {
            return HostResult::Error(2, "Quantum signature verification failed".into());
        }

        HostResult::Success(vec![1])
    }

    /// Compute SHA256 hash
    pub fn sha256(_ctx: &HostContext, data: &[u8]) -> HostResult {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        let result = hasher.finalize();
        HostResult::Success(result.to_vec())
    }

    /// Compute Keccak256 hash
    pub fn keccak256(_ctx: &HostContext, data: &[u8]) -> HostResult {
        use sha3::{Digest, Keccak256};
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        HostResult::Success(result.to_vec())
    }

    // =========================================================================
    // TEE ATTESTATION
    // =========================================================================

    /// Verify TEE attestation
    pub fn verify_tee_attestation(
        ctx: &HostContext,
        platform: u32,
        attestation: &[u8],
        expected_measurement: &[u8],
    ) -> HostResult {
        use crate::precompiles::addresses;

        let address = match platform {
            0 => addresses::TEE_VERIFY_NITRO,
            1 => addresses::TEE_VERIFY_SGX,
            2 => addresses::TEE_VERIFY_SEV,
            _ => return HostResult::Error(1, "Unknown TEE platform".into()),
        };

        // Call precompile
        match ctx
            .precompiles
            .execute(address, attestation, ctx.gas_meter.remaining())
        {
            Ok(result) if result.success => {
                // Check measurement matches if provided
                if !expected_measurement.is_empty() && result.output.len() >= 32 {
                    let measurement = &result.output[0..32];
                    if measurement != expected_measurement {
                        return HostResult::Error(2, "Measurement mismatch".into());
                    }
                }
                HostResult::Success(result.output)
            }
            Ok(_) => HostResult::Error(3, "Attestation verification failed".into()),
            Err(e) => HostResult::Error(4, format!("Precompile error: {}", e)),
        }
    }

    // =========================================================================
    // ZK PROOFS
    // =========================================================================

    /// Verify ZK proof
    pub fn verify_zkp(
        ctx: &HostContext,
        proof_type: u32,
        proof: &[u8],
        verification_key: &[u8],
        public_inputs: &[u8],
    ) -> HostResult {
        use crate::precompiles::addresses;

        let address = match proof_type {
            0 => addresses::GROTH16_VERIFY,
            1 => addresses::PLONK_VERIFY,
            2 => addresses::EZKL_VERIFY,
            3 => addresses::HALO2_VERIFY,
            _ => return HostResult::Error(1, "Unknown proof type".into()),
        };

        // Encode input for precompile
        let mut input = Vec::new();
        input.extend_from_slice(&(proof.len() as u32).to_le_bytes());
        input.extend_from_slice(proof);
        input.extend_from_slice(&(verification_key.len() as u32).to_le_bytes());
        input.extend_from_slice(verification_key);
        input.extend_from_slice(&(public_inputs.len() as u32).to_le_bytes());
        input.extend_from_slice(public_inputs);

        match ctx
            .precompiles
            .execute(address, &input, ctx.gas_meter.remaining())
        {
            Ok(result) if result.success => HostResult::Success(result.output),
            Ok(_) => HostResult::Error(2, "Proof verification failed".into()),
            Err(e) => HostResult::Error(3, format!("Precompile error: {}", e)),
        }
    }

    // =========================================================================
    // ENVIRONMENT
    // =========================================================================

    /// Get current block number
    pub fn block_number(ctx: &HostContext) -> u64 {
        ctx.block_number
    }

    /// Get current block timestamp
    pub fn block_timestamp(ctx: &HostContext) -> u64 {
        ctx.block_timestamp
    }

    /// Get chain ID
    pub fn chain_id(ctx: &HostContext) -> u64 {
        ctx.chain_id
    }

    /// Get caller address
    pub fn caller(ctx: &HostContext) -> Option<[u8; 32]> {
        ctx.caller
    }

    /// Get contract address
    pub fn contract_address(ctx: &HostContext) -> Option<[u8; 32]> {
        ctx.contract
    }

    /// Get current time (Unix timestamp)
    pub fn get_time() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    // =========================================================================
    // GAS
    // =========================================================================

    /// Get remaining gas
    pub fn gas_remaining(ctx: &HostContext) -> u64 {
        ctx.gas_meter.remaining()
    }

    /// Get gas used
    pub fn gas_used(ctx: &HostContext) -> u64 {
        ctx.gas_meter.used()
    }

    // =========================================================================
    // LOGGING
    // =========================================================================

    /// Log message
    pub fn log(level: LogLevel, message: &str) {
        match level {
            LogLevel::Trace => tracing::trace!(target: "wasm", "{}", message),
            LogLevel::Debug => tracing::debug!(target: "wasm", "{}", message),
            LogLevel::Info => tracing::info!(target: "wasm", "{}", message),
            LogLevel::Warn => tracing::warn!(target: "wasm", "{}", message),
            LogLevel::Error => tracing::error!(target: "wasm", "{}", message),
        }
    }
}

/// Log level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Trace = 0,
    Debug = 1,
    Info = 2,
    Warn = 3,
    Error = 4,
}

impl From<u32> for LogLevel {
    fn from(v: u32) -> Self {
        match v {
            0 => LogLevel::Trace,
            1 => LogLevel::Debug,
            2 => LogLevel::Info,
            3 => LogLevel::Warn,
            _ => LogLevel::Error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gas::GasMeter;
    use k256::ecdsa::signature::Signer as _;
    use k256::ecdsa::SigningKey;
    use pqcrypto_dilithium::dilithium3;

    fn create_context() -> HostContext {
        let gas_meter = Arc::new(GasMeter::with_limit(1_000_000));
        let precompiles = Arc::new(PrecompileRegistry::new());
        HostContext::new(gas_meter, precompiles)
    }

    #[test]
    fn test_sha256() {
        let ctx = create_context();
        let result = HostFunctions::sha256(&ctx, b"hello");
        assert!(result.is_success());
        assert_eq!(result.data().unwrap().len(), 32);
    }

    #[test]
    fn test_keccak256() {
        let ctx = create_context();
        let result = HostFunctions::keccak256(&ctx, b"hello");
        assert!(result.is_success());
        assert_eq!(result.data().unwrap().len(), 32);
    }

    #[test]
    fn test_block_info() {
        let gas_meter = Arc::new(GasMeter::with_limit(1_000_000));
        let precompiles = Arc::new(PrecompileRegistry::new());
        let ctx = HostContext::new(gas_meter, precompiles).with_block_info(100, 1234567890, 5);

        assert_eq!(HostFunctions::block_number(&ctx), 100);
        assert_eq!(HostFunctions::block_timestamp(&ctx), 1234567890);
        assert_eq!(HostFunctions::chain_id(&ctx), 5);
    }

    #[test]
    fn test_gas_tracking() {
        let ctx = create_context();

        assert_eq!(HostFunctions::gas_used(&ctx), 0);
        assert_eq!(HostFunctions::gas_remaining(&ctx), 1_000_000);
    }

    #[test]
    fn test_log_level() {
        assert_eq!(LogLevel::from(0), LogLevel::Trace);
        assert_eq!(LogLevel::from(1), LogLevel::Debug);
        assert_eq!(LogLevel::from(2), LogLevel::Info);
        assert_eq!(LogLevel::from(3), LogLevel::Warn);
        assert_eq!(LogLevel::from(4), LogLevel::Error);
        assert_eq!(LogLevel::from(99), LogLevel::Error);
    }

    #[test]
    fn test_verify_ecdsa_success() {
        let ctx = create_context();
        let message = b"aethelred-ecdsa-message";

        let signing_key = SigningKey::from_bytes((&[7u8; 32]).into()).expect("valid signing key");
        let sig: K256Signature = signing_key.sign(message);
        let pk = signing_key.verifying_key().to_encoded_point(true);

        let result = HostFunctions::verify_ecdsa(&ctx, message, &sig.to_bytes(), pk.as_bytes());
        assert!(
            result.is_success(),
            "expected successful ECDSA verification"
        );
    }

    #[test]
    fn test_verify_ecdsa_rejects_tampered_message() {
        let ctx = create_context();
        let message = b"aethelred-ecdsa-message";
        let tampered = b"aethelred-ecdsa-message-tampered";

        let signing_key = SigningKey::from_bytes((&[9u8; 32]).into()).expect("valid signing key");
        let sig: K256Signature = signing_key.sign(message);
        let pk = signing_key.verifying_key().to_encoded_point(true);

        let result = HostFunctions::verify_ecdsa(&ctx, tampered, &sig.to_bytes(), pk.as_bytes());
        assert!(
            matches!(result, HostResult::Error(5, _)),
            "expected ECDSA verification failure error, got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_dilithium_success() {
        let ctx = create_context();
        let message = b"aethelred-dilithium-message";

        let (pk, sk) = dilithium3::keypair();
        let sig = dilithium3::detached_sign(message, &sk);

        let result = HostFunctions::verify_dilithium(&ctx, message, sig.as_bytes(), pk.as_bytes());
        assert!(
            result.is_success(),
            "expected successful Dilithium verification"
        );
    }

    #[test]
    fn test_verify_dilithium_rejects_tampered_signature() {
        let ctx = create_context();
        let message = b"aethelred-dilithium-message";

        let (pk, sk) = dilithium3::keypair();
        let sig = dilithium3::detached_sign(message, &sk);
        let mut bad_sig = sig.as_bytes().to_vec();
        bad_sig[0] ^= 0x01;

        let result = HostFunctions::verify_dilithium(&ctx, message, &bad_sig, pk.as_bytes());
        assert!(
            matches!(result, HostResult::Error(3, _) | HostResult::Error(4, _)),
            "expected Dilithium verification failure, got {:?}",
            result
        );
    }

    #[test]
    fn test_verify_hybrid_success() {
        let ctx = create_context();
        let message = b"aethelred-hybrid-message";

        let signing_key = SigningKey::from_bytes((&[11u8; 32]).into()).expect("valid signing key");
        let classical_sig: K256Signature = signing_key.sign(message);
        let classical_pk = signing_key.verifying_key().to_encoded_point(true);

        let (quantum_pk, quantum_sk) = dilithium3::keypair();
        let quantum_sig = dilithium3::detached_sign(message, &quantum_sk);

        let result = HostFunctions::verify_hybrid(
            &ctx,
            message,
            &classical_sig.to_bytes(),
            quantum_sig.as_bytes(),
            classical_pk.as_bytes(),
            quantum_pk.as_bytes(),
        );
        assert!(
            result.is_success(),
            "expected successful hybrid verification"
        );
    }

    #[test]
    fn test_verify_hybrid_rejects_quantum_failure() {
        let ctx = create_context();
        let message = b"aethelred-hybrid-message";

        let signing_key = SigningKey::from_bytes((&[13u8; 32]).into()).expect("valid signing key");
        let classical_sig: K256Signature = signing_key.sign(message);
        let classical_pk = signing_key.verifying_key().to_encoded_point(true);

        let (quantum_pk, quantum_sk) = dilithium3::keypair();
        let mut quantum_sig = dilithium3::detached_sign(message, &quantum_sk)
            .as_bytes()
            .to_vec();
        quantum_sig[0] ^= 0x01;

        let result = HostFunctions::verify_hybrid(
            &ctx,
            message,
            &classical_sig.to_bytes(),
            &quantum_sig,
            classical_pk.as_bytes(),
            quantum_pk.as_bytes(),
        );
        assert!(
            matches!(result, HostResult::Error(2, _)),
            "expected hybrid quantum failure, got {:?}",
            result
        );
    }
}
