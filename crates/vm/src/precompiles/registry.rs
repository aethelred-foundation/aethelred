//! Precompile Registry Management
//!
//! Dynamic precompile registration and management.

use super::{ExecutionResult, Precompile, PrecompileError, PrecompileResult};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Thread-safe precompile registry
pub struct DynamicRegistry {
    /// Registered precompiles
    precompiles: RwLock<HashMap<u64, Arc<dyn Precompile>>>,
    /// Gas price multiplier
    gas_multiplier: RwLock<f64>,
    /// Registry version (incremented on changes)
    version: RwLock<u64>,
}

impl DynamicRegistry {
    /// Create new registry
    pub fn new() -> Self {
        Self {
            precompiles: RwLock::new(HashMap::new()),
            gas_multiplier: RwLock::new(1.0),
            version: RwLock::new(0),
        }
    }

    /// Register a precompile
    pub fn register(&self, precompile: Arc<dyn Precompile>) -> bool {
        let mut precompiles = self.precompiles.write().unwrap();
        let address = precompile.address();

        if precompiles.contains_key(&address) {
            return false;
        }

        precompiles.insert(address, precompile);
        *self.version.write().unwrap() += 1;
        true
    }

    /// Unregister a precompile (governance action)
    pub fn unregister(&self, address: u64) -> bool {
        let mut precompiles = self.precompiles.write().unwrap();
        let removed = precompiles.remove(&address).is_some();
        if removed {
            *self.version.write().unwrap() += 1;
        }
        removed
    }

    /// Check if address is a precompile
    pub fn is_precompile(&self, address: u64) -> bool {
        self.precompiles.read().unwrap().contains_key(&address)
    }

    /// Execute precompile
    pub fn execute(
        &self,
        address: u64,
        input: &[u8],
        gas_limit: u64,
    ) -> PrecompileResult<ExecutionResult> {
        let precompiles = self.precompiles.read().unwrap();
        let precompile = precompiles
            .get(&address)
            .ok_or(PrecompileError::NotFound(address))?;

        // Check input constraints
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
        let multiplier = *self.gas_multiplier.read().unwrap();
        let adjusted_gas = (base_gas as f64 * multiplier) as u64;

        if adjusted_gas > gas_limit {
            return Err(PrecompileError::OutOfGas {
                required: adjusted_gas,
                available: gas_limit,
            });
        }

        precompile.execute(input, gas_limit)
    }

    /// Set gas multiplier (governance action)
    pub fn set_gas_multiplier(&self, multiplier: f64) {
        *self.gas_multiplier.write().unwrap() = multiplier;
        *self.version.write().unwrap() += 1;
    }

    /// Get gas multiplier
    pub fn gas_multiplier(&self) -> f64 {
        *self.gas_multiplier.read().unwrap()
    }

    /// Get registry version
    pub fn version(&self) -> u64 {
        *self.version.read().unwrap()
    }

    /// List all precompile addresses
    pub fn addresses(&self) -> Vec<u64> {
        self.precompiles.read().unwrap().keys().copied().collect()
    }

    /// Get precompile info
    pub fn info(&self, address: u64) -> Option<PrecompileInfo> {
        self.precompiles
            .read()
            .unwrap()
            .get(&address)
            .map(|p| PrecompileInfo {
                address,
                name: p.name().to_string(),
                min_input: p.min_input_length(),
                max_input: p.max_input_length(),
                base_gas: p.gas_cost(&[]),
            })
    }

    /// Get all precompile infos
    pub fn all_info(&self) -> Vec<PrecompileInfo> {
        self.precompiles
            .read()
            .unwrap()
            .iter()
            .map(|(&addr, p)| PrecompileInfo {
                address: addr,
                name: p.name().to_string(),
                min_input: p.min_input_length(),
                max_input: p.max_input_length(),
                base_gas: p.gas_cost(&[]),
            })
            .collect()
    }
}

impl Default for DynamicRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Precompile info
#[derive(Debug, Clone)]
pub struct PrecompileInfo {
    pub address: u64,
    pub name: String,
    pub min_input: usize,
    pub max_input: usize,
    pub base_gas: u64,
}

/// Builder for creating registries with precompiles
pub struct RegistryBuilder {
    precompiles: Vec<Arc<dyn Precompile>>,
    gas_multiplier: f64,
}

impl RegistryBuilder {
    /// Create new builder
    pub fn new() -> Self {
        Self {
            precompiles: Vec::new(),
            gas_multiplier: 1.0,
        }
    }

    /// Add precompile
    pub fn add(mut self, precompile: impl Precompile + 'static) -> Self {
        self.precompiles.push(Arc::new(precompile));
        self
    }

    /// Add a precompile from an existing Arc
    pub fn add_arc(mut self, precompile: Arc<dyn Precompile>) -> Self {
        self.precompiles.push(precompile);
        self
    }

    /// Add standard precompiles
    pub fn with_standard(self) -> Self {
        self.add(super::crypto::Sha256Precompile)
            .add(super::crypto::IdentityPrecompile)
            .add(super::crypto::EcdsaRecoverPrecompile)
    }

    /// Add PQC precompiles
    pub fn with_pqc(self) -> Self {
        self.add(super::crypto::DilithiumVerifyPrecompile::new())
            .add(super::crypto::KyberDecapsPrecompile::new())
            .add(super::crypto::HybridVerifyPrecompile::new())
    }

    /// Add ZKP precompiles
    pub fn with_zkp(self) -> Self {
        let groth16 = std::sync::Arc::new(super::zkp::Groth16VerifyPrecompile::new());
        let plonk = std::sync::Arc::new(super::zkp::PlonkVerifyPrecompile::new());
        let ezkl = std::sync::Arc::new(super::zkp::EzklVerifyPrecompile::new());
        let halo2 = std::sync::Arc::new(super::zkp::Halo2VerifyPrecompile::new());
        let stark = std::sync::Arc::new(super::zkp::StarkVerifyPrecompile::new());
        let unified = super::zkp::UnifiedZkpVerifyPrecompile::new(
            groth16.clone(),
            plonk.clone(),
            ezkl.clone(),
            halo2.clone(),
            stark.clone(),
        );
        self.add_arc(groth16)
            .add_arc(plonk)
            .add_arc(ezkl)
            .add_arc(halo2)
            .add(unified)
    }

    /// Add TEE precompiles
    pub fn with_tee(self) -> Self {
        let config = super::tee::TeeVerifierConfig::default();
        let registry = Arc::new(super::tee::MeasurementRegistry::new());

        self.add(super::tee::NitroVerifyPrecompile::new(
            config.clone(),
            registry.clone(),
        ))
        .add(super::tee::SgxDcapVerifyPrecompile::new(
            config.clone(),
            registry.clone(),
        ))
        .add(super::tee::SevSnpVerifyPrecompile::new(
            config.clone(),
            registry.clone(),
        ))
        .add(super::tee::UniversalTeeVerifyPrecompile::new(config, registry))
    }

    /// Add all Aethelred precompiles
    pub fn with_aethelred(self) -> Self {
        self.with_standard().with_pqc().with_zkp().with_tee()
    }

    /// Set gas multiplier
    pub fn with_gas_multiplier(mut self, multiplier: f64) -> Self {
        self.gas_multiplier = multiplier;
        self
    }

    /// Build the registry
    pub fn build(self) -> DynamicRegistry {
        let registry = DynamicRegistry::new();
        registry.set_gas_multiplier(self.gas_multiplier);

        for precompile in self.precompiles {
            registry.register(precompile);
        }

        registry
    }
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Create default Aethelred precompile registry
pub fn create_aethelred_registry() -> DynamicRegistry {
    RegistryBuilder::new().with_aethelred().build()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dynamic_registry() {
        let registry = DynamicRegistry::new();

        // Register SHA256
        assert!(registry.register(Arc::new(super::super::crypto::Sha256Precompile)));

        // Check it's registered
        assert!(registry.is_precompile(super::super::addresses::SHA256));

        // Execute
        let result = registry
            .execute(super::super::addresses::SHA256, b"test", 1_000_000)
            .unwrap();
        assert!(result.success);
    }

    #[test]
    fn test_registry_builder() {
        let registry = RegistryBuilder::new().with_standard().with_pqc().build();

        assert!(registry.is_precompile(super::super::addresses::SHA256));
        assert!(registry.is_precompile(super::super::addresses::DILITHIUM_VERIFY));
    }

    #[test]
    fn test_registry_versioning() {
        let registry = DynamicRegistry::new();
        let v0 = registry.version();

        registry.register(Arc::new(super::super::crypto::Sha256Precompile));
        let v1 = registry.version();
        assert!(v1 > v0);

        registry.set_gas_multiplier(2.0);
        let v2 = registry.version();
        assert!(v2 > v1);
    }

    #[test]
    fn test_gas_multiplier() {
        let registry = DynamicRegistry::new();
        registry.register(Arc::new(super::super::crypto::Sha256Precompile));

        // Normal execution
        let result1 = registry
            .execute(super::super::addresses::SHA256, b"test", 1_000)
            .unwrap();
        assert!(result1.success);

        // Set high multiplier
        registry.set_gas_multiplier(1000.0);

        // Should fail due to gas limit
        let result2 = registry.execute(super::super::addresses::SHA256, b"test", 1_000);
        assert!(matches!(result2, Err(PrecompileError::OutOfGas { .. })));
    }

    #[test]
    fn test_unregister() {
        let registry = DynamicRegistry::new();
        registry.register(Arc::new(super::super::crypto::Sha256Precompile));

        assert!(registry.is_precompile(super::super::addresses::SHA256));

        registry.unregister(super::super::addresses::SHA256);

        assert!(!registry.is_precompile(super::super::addresses::SHA256));
    }

    #[test]
    fn test_aethelred_registry() {
        let registry = create_aethelred_registry();

        // Check standard
        assert!(registry.is_precompile(super::super::addresses::SHA256));

        // Check PQC
        assert!(registry.is_precompile(super::super::addresses::DILITHIUM_VERIFY));
        assert!(registry.is_precompile(super::super::addresses::HYBRID_VERIFY));

        // Check unified ZKP entry point and proof-system-specific
        assert!(registry.is_precompile(super::super::addresses::ZKP_VERIFY));
        assert!(registry.is_precompile(super::super::addresses::GROTH16_VERIFY));
        assert!(registry.is_precompile(super::super::addresses::EZKL_VERIFY));
        assert!(registry.is_precompile(super::super::addresses::HALO2_VERIFY));

        // Check unified TEE entry point and platform-specific
        assert!(registry.is_precompile(super::super::addresses::TEE_VERIFY));
        assert!(registry.is_precompile(super::super::addresses::TEE_VERIFY_NITRO));
        assert!(registry.is_precompile(super::super::addresses::TEE_VERIFY_SGX));
        assert!(registry.is_precompile(super::super::addresses::TEE_VERIFY_SEV));
    }
}
