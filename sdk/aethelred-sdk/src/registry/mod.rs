//! # Model Registry
//!
//! **"The App Store for AI"**
//!
//! A decentralized registry for AI models with:
//! - Automatic versioning
//! - License management
//! - Measurement tracking
//! - Royalty distribution

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Model Registry
// ============================================================================

/// Model registry client
pub struct ModelRegistry {
    /// Registry endpoint
    endpoint: String,
    /// Cached models
    cache: HashMap<String, ModelMetadata>,
}

impl ModelRegistry {
    /// Create a new registry client
    pub fn new(endpoint: &str) -> Self {
        ModelRegistry {
            endpoint: endpoint.to_string(),
            cache: HashMap::new(),
        }
    }

    /// Register a new model
    pub fn register(
        &mut self,
        model: ModelRegistration,
    ) -> Result<ModelId, RegistryError> {
        let id = ModelId::new(&model.name, &model.version);

        let metadata = ModelMetadata {
            id: id.clone(),
            name: model.name,
            version: model.version,
            description: model.description,
            author: model.author,
            license: model.license,
            measurements: model.measurements,
            created_at: std::time::SystemTime::now(),
            updated_at: std::time::SystemTime::now(),
            downloads: 0,
            verified: false,
        };

        self.cache.insert(id.0.clone(), metadata);

        Ok(id)
    }

    /// Get model by ID
    pub fn get(&self, id: &ModelId) -> Option<&ModelMetadata> {
        self.cache.get(&id.0)
    }

    /// Search models
    pub fn search(&self, query: &str) -> Vec<&ModelMetadata> {
        self.cache
            .values()
            .filter(|m| {
                m.name.contains(query)
                    || m.description.contains(query)
                    || m.author.contains(query)
            })
            .collect()
    }

    /// List all models
    pub fn list(&self) -> Vec<&ModelMetadata> {
        self.cache.values().collect()
    }

    /// Verify a model's measurements
    pub fn verify(&self, id: &ModelId, measurements: &ModelMeasurements) -> bool {
        if let Some(model) = self.cache.get(&id.0) {
            model.measurements.mrenclave == measurements.mrenclave
        } else {
            false
        }
    }
}

// ============================================================================
// Types
// ============================================================================

/// Model identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ModelId(pub String);

impl ModelId {
    /// Create a new model ID
    pub fn new(name: &str, version: &str) -> Self {
        ModelId(format!("{}:{}", name, version))
    }

    /// Parse a model ID
    pub fn parse(s: &str) -> Option<Self> {
        if s.contains(':') {
            Some(ModelId(s.to_string()))
        } else {
            None
        }
    }

    /// Get model name
    pub fn name(&self) -> &str {
        self.0.split(':').next().unwrap_or("")
    }

    /// Get version
    pub fn version(&self) -> &str {
        self.0.split(':').nth(1).unwrap_or("")
    }
}

/// Model registration request
#[derive(Debug, Clone)]
pub struct ModelRegistration {
    /// Model name
    pub name: String,
    /// Version (semver)
    pub version: String,
    /// Description
    pub description: String,
    /// Author
    pub author: String,
    /// License
    pub license: ModelLicense,
    /// Measurements
    pub measurements: ModelMeasurements,
}

/// Model metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMetadata {
    /// Model ID
    pub id: ModelId,
    /// Name
    pub name: String,
    /// Version
    pub version: String,
    /// Description
    pub description: String,
    /// Author
    pub author: String,
    /// License
    pub license: ModelLicense,
    /// Measurements
    pub measurements: ModelMeasurements,
    /// Created timestamp
    pub created_at: std::time::SystemTime,
    /// Updated timestamp
    pub updated_at: std::time::SystemTime,
    /// Download count
    pub downloads: u64,
    /// Verified by Aethelred
    pub verified: bool,
}

/// Model license
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelLicense {
    /// License type
    pub license_type: LicenseType,
    /// Price per inference (in AETH)
    pub price_per_inference: u64,
    /// Price per month (for subscription)
    pub price_per_month: Option<u64>,
    /// Allowed jurisdictions
    pub allowed_jurisdictions: Vec<String>,
    /// Prohibited uses
    pub prohibited_uses: Vec<String>,
    /// Attribution required
    pub attribution_required: bool,
    /// Commercial use allowed
    pub commercial_use: bool,
    /// Modification allowed
    pub modification: bool,
    /// Royalty percentage (0-100)
    pub royalty_percentage: u8,
}

/// License types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenseType {
    /// Free for all uses
    OpenSource,
    /// Pay per inference
    PayPerUse,
    /// Monthly subscription
    Subscription,
    /// Enterprise license
    Enterprise,
    /// Research only
    ResearchOnly,
    /// Custom terms
    Custom,
}

/// Model measurements (for TEE verification)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelMeasurements {
    /// MRENCLAVE (Intel SGX)
    pub mrenclave: [u8; 32],
    /// MRSIGNER (Intel SGX)
    pub mrsigner: [u8; 32],
    /// Model weights hash
    pub weights_hash: [u8; 32],
    /// Architecture hash
    pub architecture_hash: [u8; 32],
    /// Input schema hash
    pub input_schema_hash: [u8; 32],
    /// Output schema hash
    pub output_schema_hash: [u8; 32],
}

/// Model version
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelVersion {
    /// Major version
    pub major: u32,
    /// Minor version
    pub minor: u32,
    /// Patch version
    pub patch: u32,
    /// Pre-release tag
    pub prerelease: Option<String>,
}

impl ModelVersion {
    /// Parse semver string
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('.').collect();
        if parts.len() >= 3 {
            Some(ModelVersion {
                major: parts[0].parse().ok()?,
                minor: parts[1].parse().ok()?,
                patch: parts[2].parse().ok()?,
                prerelease: None,
            })
        } else {
            None
        }
    }

    /// Format as string
    pub fn to_string(&self) -> String {
        if let Some(ref pre) = self.prerelease {
            format!("{}.{}.{}-{}", self.major, self.minor, self.patch, pre)
        } else {
            format!("{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

// ============================================================================
// Foundry
// ============================================================================

/// Model Foundry - Build and deploy models
pub struct ModelFoundry {
    /// Registry
    registry: ModelRegistry,
}

impl ModelFoundry {
    /// Create a new foundry
    pub fn new(registry: ModelRegistry) -> Self {
        ModelFoundry { registry }
    }

    /// Build model from ONNX
    pub fn build_from_onnx(
        &self,
        _onnx_path: &std::path::Path,
        _config: BuildConfig,
    ) -> Result<BuiltModel, RegistryError> {
        // In production, this would:
        // 1. Load ONNX model
        // 2. Compile for target TEE
        // 3. Generate EZKL circuit
        // 4. Calculate measurements

        Ok(BuiltModel {
            bytecode: vec![],
            measurements: ModelMeasurements {
                mrenclave: [0u8; 32],
                mrsigner: [0u8; 32],
                weights_hash: [0u8; 32],
                architecture_hash: [0u8; 32],
                input_schema_hash: [0u8; 32],
                output_schema_hash: [0u8; 32],
            },
        })
    }

    /// Deploy model
    pub fn deploy(
        &mut self,
        model: BuiltModel,
        registration: ModelRegistration,
    ) -> Result<ModelId, RegistryError> {
        self.registry.register(registration)
    }
}

/// Build configuration
#[derive(Debug, Clone)]
pub struct BuildConfig {
    /// Target TEE
    pub target: crate::attestation::HardwareType,
    /// Optimization level
    pub opt_level: u8,
    /// Enable quantization
    pub quantize: bool,
}

/// Built model
#[derive(Debug, Clone)]
pub struct BuiltModel {
    /// Compiled bytecode
    pub bytecode: Vec<u8>,
    /// Measurements
    pub measurements: ModelMeasurements,
}

// ============================================================================
// Errors
// ============================================================================

/// Registry errors
#[derive(Debug, Clone, thiserror::Error)]
pub enum RegistryError {
    /// Model not found
    #[error("Model not found: {0}")]
    NotFound(String),

    /// Model already exists
    #[error("Model already exists: {0}")]
    AlreadyExists(String),

    /// Invalid version
    #[error("Invalid version: {0}")]
    InvalidVersion(String),

    /// License violation
    #[error("License violation: {0}")]
    LicenseViolation(String),

    /// Network error
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Build error
    #[error("Build error: {0}")]
    BuildError(String),
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_model_id() {
        let id = ModelId::new("credit-scoring", "1.0.0");
        assert_eq!(id.name(), "credit-scoring");
        assert_eq!(id.version(), "1.0.0");
    }

    #[test]
    fn test_version_parse() {
        let v = ModelVersion::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
    }

    #[test]
    fn test_registry() {
        let mut registry = ModelRegistry::new("http://localhost");

        let registration = ModelRegistration {
            name: "test-model".to_string(),
            version: "1.0.0".to_string(),
            description: "Test".to_string(),
            author: "test".to_string(),
            license: ModelLicense {
                license_type: LicenseType::OpenSource,
                price_per_inference: 0,
                price_per_month: None,
                allowed_jurisdictions: vec![],
                prohibited_uses: vec![],
                attribution_required: false,
                commercial_use: true,
                modification: true,
                royalty_percentage: 0,
            },
            measurements: ModelMeasurements {
                mrenclave: [0u8; 32],
                mrsigner: [0u8; 32],
                weights_hash: [0u8; 32],
                architecture_hash: [0u8; 32],
                input_schema_hash: [0u8; 32],
                output_schema_hash: [0u8; 32],
            },
        };

        let id = registry.register(registration).unwrap();
        assert!(registry.get(&id).is_some());
    }
}
