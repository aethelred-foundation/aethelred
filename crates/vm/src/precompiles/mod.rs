//! Aethelred VM Pre-Compiles
//!
//! Enterprise-grade pre-compiled contracts for cryptographic verification.
//!
//! # Pre-Compile Addresses
//!
//! | Address | Name | Description |
//! |---------|------|-------------|
//! | 0x0001 | ECDSA_RECOVER | Recover ECDSA public key from signature |
//! | 0x0002 | SHA256 | SHA-256 hash |
//! | 0x0003 | RIPEMD160 | RIPEMD-160 hash |
//! | 0x0004 | IDENTITY | Data copy |
//! | 0x0005 | MODEXP | Modular exponentiation |
//! | 0x0006 | BN_ADD | BN256 curve point addition |
//! | 0x0007 | BN_MUL | BN256 curve point multiplication |
//! | 0x0008 | BN_PAIRING | BN256 pairing check |
//! | 0x0009 | BLAKE2F | BLAKE2b compression |
//! | 0x0100 | DILITHIUM_VERIFY | Dilithium3 signature verification |
//! | 0x0101 | KYBER_DECAPS | Kyber768 decapsulation |
//! | 0x0102 | HYBRID_VERIFY | Hybrid (ECDSA + Dilithium) verification |
//! | 0x0300 | ZKP_VERIFY | Unified ZK proof verification (auto-routes) |
//! | 0x0301 | GROTH16_VERIFY | Groth16 zkSNARK verification |
//! | 0x0302 | PLONK_VERIFY | PLONK zkSNARK verification |
//! | 0x0303 | EZKL_VERIFY | EZKL zkML proof verification |
//! | 0x0304 | HALO2_VERIFY | Halo2 proof verification |
//! | 0x0305 | BATCH_GROTH16_VERIFY | Batch Groth16 verification (amortized) |
//! | 0x0306 | STARK_VERIFY | STARK (FRI-based) proof verification |
//! | 0x0400 | TEE_VERIFY | Unified TEE attestation verification (auto-routes) |
//! | 0x0401 | TEE_VERIFY_NITRO | AWS Nitro attestation verification |
//! | 0x0402 | TEE_VERIFY_SGX | Intel SGX attestation verification |
//! | 0x0403 | TEE_VERIFY_SEV | AMD SEV-SNP attestation verification |

pub mod crypto;
pub mod registry;
pub mod tee;
pub mod zkp;

use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;

/// Pre-compile errors
#[derive(Error, Debug, Clone)]
pub enum PrecompileError {
    #[error("Invalid input length: expected {expected}, got {actual}")]
    InvalidInputLength { expected: usize, actual: usize },

    #[error("Invalid input format: {0}")]
    InvalidInputFormat(String),

    #[error("Verification failed: {0}")]
    VerificationFailed(String),

    #[error("Out of gas: required {required}, available {available}")]
    OutOfGas { required: u64, available: u64 },

    #[error("Precompile not found at address {0:#06x}")]
    NotFound(u64),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("Unsupported operation: {0}")]
    UnsupportedOperation(String),
}

/// Result type for precompile operations
pub type PrecompileResult<T> = Result<T, PrecompileError>;

/// Pre-compile execution result
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Output data
    pub output: Vec<u8>,
    /// Gas used
    pub gas_used: u64,
    /// Success flag
    pub success: bool,
}

impl ExecutionResult {
    /// Create success result
    pub fn success(output: Vec<u8>, gas_used: u64) -> Self {
        Self {
            output,
            gas_used,
            success: true,
        }
    }

    /// Create failure result
    pub fn failure(gas_used: u64) -> Self {
        Self {
            output: Vec::new(),
            gas_used,
            success: false,
        }
    }
}

/// Pre-compile trait
pub trait Precompile: Send + Sync {
    /// Get pre-compile address
    fn address(&self) -> u64;

    /// Get pre-compile name
    fn name(&self) -> &'static str;

    /// Calculate gas cost for input
    fn gas_cost(&self, input: &[u8]) -> u64;

    /// Execute pre-compile
    fn execute(&self, input: &[u8], gas_limit: u64) -> PrecompileResult<ExecutionResult>;

    /// Get minimum input length
    fn min_input_length(&self) -> usize {
        0
    }

    /// Get maximum input length (0 = unlimited)
    fn max_input_length(&self) -> usize {
        0
    }
}

/// Pre-compile addresses
pub mod addresses {
    // Standard Ethereum precompiles
    pub const ECDSA_RECOVER: u64 = 0x0001;
    pub const SHA256: u64 = 0x0002;
    pub const RIPEMD160: u64 = 0x0003;
    pub const IDENTITY: u64 = 0x0004;
    pub const MODEXP: u64 = 0x0005;
    pub const BN_ADD: u64 = 0x0006;
    pub const BN_MUL: u64 = 0x0007;
    pub const BN_PAIRING: u64 = 0x0008;
    pub const BLAKE2F: u64 = 0x0009;

    // Aethelred PQC precompiles
    pub const DILITHIUM_VERIFY: u64 = 0x0100;
    pub const KYBER_DECAPS: u64 = 0x0101;
    pub const HYBRID_VERIFY: u64 = 0x0102;
    pub const DILITHIUM5_VERIFY: u64 = 0x0103;
    pub const KYBER1024_DECAPS: u64 = 0x0104;

    // ZK proof verification precompiles (0x0300 range)
    // 0x0300 is the unified entry point; 0x0301+ are proof-system-specific
    pub const ZKP_VERIFY: u64 = 0x0300;
    pub const GROTH16_VERIFY: u64 = 0x0301;
    pub const PLONK_VERIFY: u64 = 0x0302;
    pub const EZKL_VERIFY: u64 = 0x0303;
    pub const HALO2_VERIFY: u64 = 0x0304;
    pub const BATCH_GROTH16_VERIFY: u64 = 0x0305;
    pub const STARK_VERIFY: u64 = 0x0306;

    // TEE attestation verification precompiles (0x0400 range)
    // 0x0400 is the unified entry point; 0x0401+ are platform-specific
    pub const TEE_VERIFY: u64 = 0x0400;
    pub const TEE_VERIFY_NITRO: u64 = 0x0401;
    pub const TEE_VERIFY_SGX: u64 = 0x0402;
    pub const TEE_VERIFY_SEV: u64 = 0x0403;

    // Aethelred-specific precompiles (0x0500 range)
    pub const SEAL_VERIFY: u64 = 0x0500;
    pub const ORACLE_VERIFY: u64 = 0x0501;
}

/// Pre-compile registry
pub struct PrecompileRegistry {
    /// Registered pre-compiles by address
    precompiles: HashMap<u64, Arc<dyn Precompile>>,
    /// Gas price multiplier (for dynamic pricing)
    gas_multiplier: f64,
}

impl PrecompileRegistry {
    /// Create new registry with standard precompiles
    pub fn new() -> Self {
        let mut registry = Self {
            precompiles: HashMap::new(),
            gas_multiplier: 1.0,
        };

        // Register standard precompiles
        registry.register_standard_precompiles();

        // Register Aethelred precompiles
        registry.register_pqc_precompiles();
        registry.register_zkp_precompiles();
        registry.register_tee_precompiles();

        registry
    }

    /// Create minimal registry (for testing)
    pub fn minimal() -> Self {
        Self {
            precompiles: HashMap::new(),
            gas_multiplier: 1.0,
        }
    }

    /// Register a precompile
    pub fn register(&mut self, precompile: Arc<dyn Precompile>) {
        self.precompiles.insert(precompile.address(), precompile);
    }

    /// Check if address is a precompile
    pub fn is_precompile(&self, address: u64) -> bool {
        self.precompiles.contains_key(&address)
    }

    /// Get precompile by address
    pub fn get(&self, address: u64) -> Option<&Arc<dyn Precompile>> {
        self.precompiles.get(&address)
    }

    /// Execute precompile
    pub fn execute(
        &self,
        address: u64,
        input: &[u8],
        gas_limit: u64,
    ) -> PrecompileResult<ExecutionResult> {
        let precompile = self
            .precompiles
            .get(&address)
            .ok_or(PrecompileError::NotFound(address))?;

        // Check input length constraints
        let min_len = precompile.min_input_length();
        if input.len() < min_len {
            return Err(PrecompileError::InvalidInputLength {
                expected: min_len,
                actual: input.len(),
            });
        }

        let max_len = precompile.max_input_length();
        if max_len > 0 && input.len() > max_len {
            return Err(PrecompileError::InvalidInputLength {
                expected: max_len,
                actual: input.len(),
            });
        }

        // Calculate gas with multiplier
        let base_gas = precompile.gas_cost(input);
        let adjusted_gas = (base_gas as f64 * self.gas_multiplier) as u64;

        if adjusted_gas > gas_limit {
            return Err(PrecompileError::OutOfGas {
                required: adjusted_gas,
                available: gas_limit,
            });
        }

        precompile.execute(input, gas_limit)
    }

    /// Set gas multiplier
    pub fn set_gas_multiplier(&mut self, multiplier: f64) {
        self.gas_multiplier = multiplier;
    }

    /// Get all registered precompile addresses
    pub fn addresses(&self) -> Vec<u64> {
        self.precompiles.keys().copied().collect()
    }

    /// Get precompile info
    pub fn info(&self, address: u64) -> Option<PrecompileInfo> {
        self.precompiles.get(&address).map(|p| PrecompileInfo {
            address,
            name: p.name(),
            min_input: p.min_input_length(),
            max_input: p.max_input_length(),
        })
    }

    /// Register standard Ethereum precompiles
    fn register_standard_precompiles(&mut self) {
        self.register(Arc::new(crypto::Sha256Precompile));
        self.register(Arc::new(crypto::IdentityPrecompile));
        self.register(Arc::new(crypto::EcdsaRecoverPrecompile));
    }

    /// Register PQC precompiles
    fn register_pqc_precompiles(&mut self) {
        self.register(Arc::new(crypto::DilithiumVerifyPrecompile::new()));
        self.register(Arc::new(crypto::KyberDecapsPrecompile::new()));
        self.register(Arc::new(crypto::HybridVerifyPrecompile::new()));
    }

    /// Register ZK proof precompiles
    fn register_zkp_precompiles(&mut self) {
        let groth16 = Arc::new(zkp::Groth16VerifyPrecompile::new());
        let plonk = Arc::new(zkp::PlonkVerifyPrecompile::new());
        let ezkl = Arc::new(zkp::EzklVerifyPrecompile::new());
        let halo2 = Arc::new(zkp::Halo2VerifyPrecompile::new());
        let stark = Arc::new(zkp::StarkVerifyPrecompile::new());

        // Register unified ZKP precompile at primary 0x0300 address
        self.register(Arc::new(zkp::UnifiedZkpVerifyPrecompile::new(
            groth16.clone(),
            plonk.clone(),
            ezkl.clone(),
            halo2.clone(),
            stark.clone(),
        )));

        // Register proof-system-specific precompiles at 0x0301+
        self.register(groth16);
        self.register(plonk);
        self.register(ezkl);
        self.register(halo2);
        self.register(stark);

        // Batch Groth16 verification at 0x0305
        self.register(Arc::new(zkp::BatchGroth16VerifyPrecompile::new()));
    }

    /// Register TEE attestation precompiles
    fn register_tee_precompiles(&mut self) {
        use std::sync::Arc as StdArc;
        use tee::{MeasurementRegistry, TeeVerifierConfig};

        let config = TeeVerifierConfig::default();
        let registry = StdArc::new(MeasurementRegistry::new());

        // Register unified TEE precompile at primary 0x0400 address
        self.register(Arc::new(tee::UniversalTeeVerifyPrecompile::new(
            config.clone(),
            registry.clone(),
        )));

        // Register platform-specific precompiles at 0x0401+
        self.register(Arc::new(tee::NitroVerifyPrecompile::new(
            config.clone(),
            registry.clone(),
        )));
        self.register(Arc::new(tee::SgxDcapVerifyPrecompile::new(
            config.clone(),
            registry.clone(),
        )));
        self.register(Arc::new(tee::SevSnpVerifyPrecompile::new(config, registry)));
    }
}

impl Default for PrecompileRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Precompile information
#[derive(Debug, Clone)]
pub struct PrecompileInfo {
    pub address: u64,
    pub name: &'static str,
    pub min_input: usize,
    pub max_input: usize,
}

/// Gas costs for precompiles
pub mod gas_costs {
    /// Base gas for SHA256
    pub const SHA256_BASE: u64 = 60;
    pub const SHA256_PER_WORD: u64 = 12;

    /// Base gas for ECDSA recover
    pub const ECDSA_RECOVER: u64 = 3000;

    /// Base gas for identity (data copy)
    pub const IDENTITY_BASE: u64 = 15;
    pub const IDENTITY_PER_WORD: u64 = 3;

    /// Dilithium verification gas
    pub const DILITHIUM3_VERIFY: u64 = 10_000;
    pub const DILITHIUM5_VERIFY: u64 = 15_000;

    /// Kyber decapsulation gas
    pub const KYBER768_DECAPS: u64 = 5_000;
    pub const KYBER1024_DECAPS: u64 = 7_000;

    /// Hybrid verification gas
    pub const HYBRID_VERIFY: u64 = 13_000; // ECDSA + Dilithium3

    /// Groth16 verification gas
    pub const GROTH16_BASE: u64 = 150_000;
    pub const GROTH16_PER_PUBLIC_INPUT: u64 = 20_000;

    /// PLONK verification gas
    pub const PLONK_BASE: u64 = 200_000;

    /// EZKL verification gas
    pub const EZKL_BASE: u64 = 250_000;

    /// Batch Groth16 verification gas (amortized: ~40% cheaper per proof)
    pub const BATCH_GROTH16_BASE: u64 = 100_000;
    pub const BATCH_GROTH16_PER_PROOF: u64 = 80_000;
    pub const BATCH_GROTH16_PER_PUBLIC_INPUT: u64 = 12_000;

    /// STARK verification gas (FRI-based proofs are larger)
    pub const STARK_BASE: u64 = 300_000;

    /// Unified ZKP routing overhead (added on top of proof-system-specific cost)
    pub const ZKP_UNIFIED_OVERHEAD: u64 = 5_000;

    /// TEE attestation verification gas
    pub const NITRO_VERIFY: u64 = 200_000;
    pub const SGX_VERIFY: u64 = 500_000;
    pub const SEV_VERIFY: u64 = 300_000;
}

/// Helper to calculate word-based gas costs
pub fn word_gas_cost(base: u64, per_word: u64, data_len: usize) -> u64 {
    let words = data_len.div_ceil(32);
    base + (words as u64) * per_word
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registry_creation() {
        let registry = PrecompileRegistry::new();
        assert!(registry.is_precompile(addresses::SHA256));
        assert!(registry.is_precompile(addresses::DILITHIUM_VERIFY));

        // Unified entry points at primary addresses
        assert!(registry.is_precompile(addresses::ZKP_VERIFY));
        assert!(registry.is_precompile(addresses::TEE_VERIFY));

        // Proof-system-specific precompiles
        assert!(registry.is_precompile(addresses::GROTH16_VERIFY));
        assert!(registry.is_precompile(addresses::EZKL_VERIFY));
        assert!(registry.is_precompile(addresses::HALO2_VERIFY));

        // Platform-specific TEE precompiles
        assert!(registry.is_precompile(addresses::TEE_VERIFY_NITRO));
        assert!(registry.is_precompile(addresses::TEE_VERIFY_SGX));
        assert!(registry.is_precompile(addresses::TEE_VERIFY_SEV));
    }

    #[test]
    fn test_precompile_not_found() {
        let registry = PrecompileRegistry::new();
        let result = registry.execute(0xFFFF, &[], 1_000_000);
        assert!(matches!(result, Err(PrecompileError::NotFound(0xFFFF))));
    }

    #[test]
    fn test_sha256_precompile() {
        let registry = PrecompileRegistry::new();
        let input = b"hello world";
        let result = registry
            .execute(addresses::SHA256, input, 1_000_000)
            .unwrap();
        assert!(result.success);
        assert_eq!(result.output.len(), 32);
    }

    #[test]
    fn test_identity_precompile() {
        let registry = PrecompileRegistry::new();
        let input = b"test data";
        let result = registry
            .execute(addresses::IDENTITY, input, 1_000_000)
            .unwrap();
        assert!(result.success);
        assert_eq!(result.output, input);
    }

    #[test]
    fn test_gas_multiplier() {
        let mut registry = PrecompileRegistry::new();
        registry.set_gas_multiplier(2.0);

        let result = registry
            .execute(addresses::IDENTITY, &[0; 100], 10)
            .unwrap_err();
        assert!(matches!(result, PrecompileError::OutOfGas { .. }));
    }

    #[test]
    fn test_precompile_info() {
        let registry = PrecompileRegistry::new();
        let info = registry.info(addresses::SHA256).unwrap();
        assert_eq!(info.name, "SHA256");
    }

    #[test]
    fn test_word_gas_calculation() {
        assert_eq!(word_gas_cost(60, 12, 0), 60);
        assert_eq!(word_gas_cost(60, 12, 32), 72);
        assert_eq!(word_gas_cost(60, 12, 64), 84);
        assert_eq!(word_gas_cost(60, 12, 33), 84); // Rounds up
    }
}
