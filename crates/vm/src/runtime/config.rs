//! WASM Runtime Configuration
//!
//! Enterprise-grade configuration for the Aethelred WASM runtime.

use crate::error::{VmError, VmResult};
use crate::gas::GasConfig;
use crate::memory::MemoryLimits;
use serde::{Deserialize, Serialize};

/// WASM runtime configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WasmConfig {
    // =========================================================================
    // COMPILER SETTINGS
    // =========================================================================
    /// Compiler backend: "cranelift" or "singlepass"
    pub compiler: String,

    /// Enable compiler optimizations
    pub enable_optimizations: bool,

    /// Enable gas metering middleware
    pub enable_gas_metering: bool,

    // =========================================================================
    // EXECUTION LIMITS
    // =========================================================================
    /// Maximum bytecode size in bytes
    pub max_bytecode_size: usize,

    /// Maximum execution time in milliseconds (0 = unlimited)
    pub max_execution_time_ms: u64,

    /// Maximum function call depth
    pub max_call_depth: u32,

    /// Maximum stack size in bytes
    pub max_stack_size: u64,

    // =========================================================================
    // MEMORY
    // =========================================================================
    /// Memory limits
    pub memory_limits: MemoryLimits,

    /// Initial memory pages
    pub initial_memory_pages: u32,

    /// Maximum memory pages
    pub max_memory_pages: u32,

    // =========================================================================
    // GAS
    // =========================================================================
    /// Gas configuration
    pub gas_config: GasConfig,

    /// Default gas limit for executions
    pub default_gas_limit: u64,

    // =========================================================================
    // CACHING
    // =========================================================================
    /// Enable module caching
    pub enable_caching: bool,

    /// Module cache size
    pub module_cache_size: usize,

    // =========================================================================
    // FEATURES
    // =========================================================================
    /// Enable SIMD instructions
    pub enable_simd: bool,

    /// Enable threads (WASM threads proposal)
    pub enable_threads: bool,

    /// Enable reference types
    pub enable_reference_types: bool,

    /// Enable bulk memory operations
    pub enable_bulk_memory: bool,

    /// Enable multi-value returns
    pub enable_multi_value: bool,

    // =========================================================================
    // SECURITY
    // =========================================================================
    /// Enable deterministic execution
    pub deterministic: bool,

    /// Enable strict validation
    pub strict_validation: bool,

    /// Enable bounds checking
    pub bounds_checking: bool,
}

impl Default for WasmConfig {
    fn default() -> Self {
        Self::production()
    }
}

impl WasmConfig {
    /// Production configuration (secure, optimized)
    pub fn production() -> Self {
        Self {
            // Compiler
            compiler: "cranelift".to_string(),
            enable_optimizations: true,
            enable_gas_metering: true,

            // Execution limits
            max_bytecode_size: 10 * 1024 * 1024, // 10MB
            max_execution_time_ms: 30_000,       // 30 seconds
            max_call_depth: 500,
            max_stack_size: 1024 * 1024, // 1MB

            // Memory
            memory_limits: MemoryLimits::production(),
            initial_memory_pages: 16,
            max_memory_pages: 512,

            // Gas
            gas_config: GasConfig::production(),
            default_gas_limit: 10_000_000,

            // Caching
            enable_caching: true,
            module_cache_size: 100,

            // Features - conservative for security
            enable_simd: false,
            enable_threads: false,
            enable_reference_types: false,
            enable_bulk_memory: true,
            enable_multi_value: true,

            // Security
            deterministic: true,
            strict_validation: true,
            bounds_checking: true,
        }
    }

    /// Development configuration (faster compilation)
    pub fn development() -> Self {
        Self {
            // Compiler - faster compilation
            compiler: "singlepass".to_string(),
            enable_optimizations: false,
            enable_gas_metering: false,

            // Execution limits - relaxed
            max_bytecode_size: 50 * 1024 * 1024, // 50MB
            max_execution_time_ms: 0,            // Unlimited
            max_call_depth: 1000,
            max_stack_size: 4 * 1024 * 1024, // 4MB

            // Memory - relaxed
            memory_limits: MemoryLimits::ml_workload(),
            initial_memory_pages: 256,
            max_memory_pages: 4096,

            // Gas - disabled
            gas_config: GasConfig::testing(),
            default_gas_limit: u64::MAX,

            // Caching
            enable_caching: true,
            module_cache_size: 10,

            // Features - all enabled
            enable_simd: true,
            enable_threads: true,
            enable_reference_types: true,
            enable_bulk_memory: true,
            enable_multi_value: true,

            // Security - relaxed for debugging
            deterministic: false,
            strict_validation: false,
            bounds_checking: true,
        }
    }

    /// Testing configuration (minimal)
    pub fn testing() -> Self {
        Self {
            // Compiler
            compiler: "singlepass".to_string(),
            enable_optimizations: false,
            enable_gas_metering: false,

            // Execution limits
            max_bytecode_size: 1024 * 1024,
            max_execution_time_ms: 5_000,
            max_call_depth: 100,
            max_stack_size: 64 * 1024,

            // Memory
            memory_limits: MemoryLimits::testing(),
            initial_memory_pages: 1,
            max_memory_pages: 16,

            // Gas
            gas_config: GasConfig::testing(),
            default_gas_limit: 1_000_000,

            // Caching
            enable_caching: false,
            module_cache_size: 1,

            // Features
            enable_simd: false,
            enable_threads: false,
            enable_reference_types: false,
            enable_bulk_memory: false,
            enable_multi_value: false,

            // Security
            deterministic: true,
            strict_validation: true,
            bounds_checking: true,
        }
    }

    /// ML inference configuration (optimized for AI workloads)
    pub fn ml_inference() -> Self {
        Self {
            // Compiler - optimized
            compiler: "cranelift".to_string(),
            enable_optimizations: true,
            enable_gas_metering: true,

            // Execution limits - extended for ML
            max_bytecode_size: 100 * 1024 * 1024, // 100MB for models
            max_execution_time_ms: 300_000,       // 5 minutes
            max_call_depth: 1000,
            max_stack_size: 8 * 1024 * 1024, // 8MB

            // Memory - large for ML
            memory_limits: MemoryLimits::ml_workload(),
            initial_memory_pages: 1024, // 64MB
            max_memory_pages: 16384,    // 1GB

            // Gas - ML-specific costs
            gas_config: GasConfig::production(),
            default_gas_limit: 100_000_000,

            // Caching
            enable_caching: true,
            module_cache_size: 50,

            // Features - SIMD for ML
            enable_simd: true,
            enable_threads: false,
            enable_reference_types: false,
            enable_bulk_memory: true,
            enable_multi_value: true,

            // Security
            deterministic: true,
            strict_validation: true,
            bounds_checking: true,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> VmResult<()> {
        // Compiler
        if !["cranelift", "singlepass"].contains(&self.compiler.as_str()) {
            return Err(VmError::Config(format!(
                "Invalid compiler: {} (must be 'cranelift' or 'singlepass')",
                self.compiler
            )));
        }

        // Memory pages
        if self.initial_memory_pages > self.max_memory_pages {
            return Err(VmError::Config(
                "Initial memory pages cannot exceed max memory pages".into(),
            ));
        }

        // WASM limits
        if self.max_memory_pages > 65536 {
            return Err(VmError::Config(
                "Max memory pages cannot exceed 65536 (4GB limit)".into(),
            ));
        }

        // Cache size
        if self.enable_caching && self.module_cache_size == 0 {
            return Err(VmError::Config(
                "Module cache size must be > 0 when caching is enabled".into(),
            ));
        }

        // Stack size
        if self.max_stack_size == 0 {
            return Err(VmError::Config("Max stack size cannot be zero".into()));
        }

        Ok(())
    }

    /// Create builder
    pub fn builder() -> WasmConfigBuilder {
        WasmConfigBuilder::new()
    }
}

/// Builder for WasmConfig
pub struct WasmConfigBuilder {
    config: WasmConfig,
}

impl WasmConfigBuilder {
    /// Create new builder with production defaults
    pub fn new() -> Self {
        Self {
            config: WasmConfig::production(),
        }
    }

    /// Set compiler
    pub fn compiler(mut self, compiler: &str) -> Self {
        self.config.compiler = compiler.to_string();
        self
    }

    /// Enable optimizations
    pub fn optimizations(mut self, enable: bool) -> Self {
        self.config.enable_optimizations = enable;
        self
    }

    /// Enable gas metering
    pub fn gas_metering(mut self, enable: bool) -> Self {
        self.config.enable_gas_metering = enable;
        self
    }

    /// Set max bytecode size
    pub fn max_bytecode_size(mut self, size: usize) -> Self {
        self.config.max_bytecode_size = size;
        self
    }

    /// Set max execution time
    pub fn max_execution_time_ms(mut self, ms: u64) -> Self {
        self.config.max_execution_time_ms = ms;
        self
    }

    /// Set max call depth
    pub fn max_call_depth(mut self, depth: u32) -> Self {
        self.config.max_call_depth = depth;
        self
    }

    /// Set initial memory pages
    pub fn initial_memory_pages(mut self, pages: u32) -> Self {
        self.config.initial_memory_pages = pages;
        self
    }

    /// Set max memory pages
    pub fn max_memory_pages(mut self, pages: u32) -> Self {
        self.config.max_memory_pages = pages;
        self
    }

    /// Set gas config
    pub fn gas_config(mut self, config: GasConfig) -> Self {
        self.config.gas_config = config;
        self
    }

    /// Set default gas limit
    pub fn default_gas_limit(mut self, limit: u64) -> Self {
        self.config.default_gas_limit = limit;
        self
    }

    /// Enable caching
    pub fn caching(mut self, enable: bool, size: usize) -> Self {
        self.config.enable_caching = enable;
        self.config.module_cache_size = size;
        self
    }

    /// Enable SIMD
    pub fn simd(mut self, enable: bool) -> Self {
        self.config.enable_simd = enable;
        self
    }

    /// Enable deterministic mode
    pub fn deterministic(mut self, enable: bool) -> Self {
        self.config.deterministic = enable;
        self
    }

    /// Build configuration
    pub fn build(self) -> VmResult<WasmConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

impl Default for WasmConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_presets() {
        let prod = WasmConfig::production();
        let dev = WasmConfig::development();
        let test = WasmConfig::testing();
        let ml = WasmConfig::ml_inference();

        assert!(prod.validate().is_ok());
        assert!(dev.validate().is_ok());
        assert!(test.validate().is_ok());
        assert!(ml.validate().is_ok());

        // Production should have gas metering
        assert!(prod.enable_gas_metering);

        // Development should have no gas metering
        assert!(!dev.enable_gas_metering);

        // ML should have larger memory
        assert!(ml.max_memory_pages > prod.max_memory_pages);
    }

    #[test]
    fn test_config_validation() {
        let mut config = WasmConfig::production();

        // Invalid compiler
        config.compiler = "invalid".to_string();
        assert!(config.validate().is_err());
        config.compiler = "cranelift".to_string();

        // Invalid memory pages
        config.initial_memory_pages = 1000;
        config.max_memory_pages = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_builder() {
        let config = WasmConfig::builder()
            .compiler("singlepass")
            .optimizations(false)
            .max_bytecode_size(1024 * 1024)
            .max_memory_pages(256)
            .build()
            .unwrap();

        assert_eq!(config.compiler, "singlepass");
        assert!(!config.enable_optimizations);
        assert_eq!(config.max_bytecode_size, 1024 * 1024);
        assert_eq!(config.max_memory_pages, 256);
    }
}
