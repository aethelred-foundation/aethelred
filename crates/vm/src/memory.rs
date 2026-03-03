//! Memory Management
//!
//! Enterprise-grade memory management for WASM execution with sandboxing.

use serde::{Deserialize, Serialize};

/// Memory configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryConfig {
    /// Initial memory pages (64KB each)
    pub initial_pages: u32,
    /// Maximum memory pages
    pub max_pages: u32,
    /// Enable memory bounds checking
    pub bounds_checking: bool,
    /// Enable memory zeroing on allocation
    pub zero_on_alloc: bool,
    /// Enable guard pages
    pub guard_pages: bool,
    /// Stack size in bytes
    pub stack_size: u64,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            initial_pages: 16, // 1MB
            max_pages: 256,    // 16MB
            bounds_checking: true,
            zero_on_alloc: true,
            guard_pages: true,
            stack_size: 1024 * 1024, // 1MB stack
        }
    }
}

impl MemoryConfig {
    /// Production configuration (more restrictive)
    pub fn production() -> Self {
        Self {
            initial_pages: 16,
            max_pages: 512, // 32MB max
            bounds_checking: true,
            zero_on_alloc: true,
            guard_pages: true,
            stack_size: 512 * 1024, // 512KB stack
        }
    }

    /// Large memory configuration for ML workloads
    pub fn ml_workload() -> Self {
        Self {
            initial_pages: 256, // 16MB
            max_pages: 8192,    // 512MB max
            bounds_checking: true,
            zero_on_alloc: false, // Skip for performance
            guard_pages: true,
            stack_size: 2 * 1024 * 1024, // 2MB stack
        }
    }

    /// Testing configuration (minimal)
    pub fn testing() -> Self {
        Self {
            initial_pages: 1,
            max_pages: 16,
            bounds_checking: false,
            zero_on_alloc: false,
            guard_pages: false,
            stack_size: 64 * 1024,
        }
    }

    /// Get initial memory in bytes
    pub fn initial_bytes(&self) -> u64 {
        self.initial_pages as u64 * 65536
    }

    /// Get maximum memory in bytes
    pub fn max_bytes(&self) -> u64 {
        self.max_pages as u64 * 65536
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        if self.initial_pages > self.max_pages {
            return Err("Initial pages cannot exceed max pages".into());
        }
        if self.max_pages > 65536 {
            return Err("Max pages cannot exceed 65536 (4GB)".into());
        }
        if self.stack_size == 0 {
            return Err("Stack size cannot be zero".into());
        }
        Ok(())
    }
}

/// Memory limits for WASM execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLimits {
    /// Maximum memory per instance in bytes
    pub max_instance_memory: u64,
    /// Maximum total memory across all instances
    pub max_total_memory: u64,
    /// Maximum stack depth
    pub max_stack_depth: u32,
    /// Maximum call depth
    pub max_call_depth: u32,
    /// Maximum table elements
    pub max_table_elements: u32,
    /// Maximum globals
    pub max_globals: u32,
    /// Maximum functions
    pub max_functions: u32,
}

impl Default for MemoryLimits {
    fn default() -> Self {
        Self {
            max_instance_memory: 32 * 1024 * 1024, // 32MB
            max_total_memory: 512 * 1024 * 1024,   // 512MB
            max_stack_depth: 10_000,
            max_call_depth: 1000,
            max_table_elements: 10_000,
            max_globals: 1000,
            max_functions: 10_000,
        }
    }
}

impl MemoryLimits {
    /// Production limits
    pub fn production() -> Self {
        Self {
            max_instance_memory: 64 * 1024 * 1024,
            max_total_memory: 1024 * 1024 * 1024,
            max_stack_depth: 50_000,
            max_call_depth: 500,
            max_table_elements: 10_000,
            max_globals: 1000,
            max_functions: 50_000,
        }
    }

    /// ML workload limits
    pub fn ml_workload() -> Self {
        Self {
            max_instance_memory: 512 * 1024 * 1024,
            max_total_memory: 2 * 1024 * 1024 * 1024,
            max_stack_depth: 100_000,
            max_call_depth: 2000,
            max_table_elements: 100_000,
            max_globals: 10_000,
            max_functions: 100_000,
        }
    }

    /// Testing limits
    pub fn testing() -> Self {
        Self {
            max_instance_memory: 1024 * 1024,
            max_total_memory: 10 * 1024 * 1024,
            max_stack_depth: 1000,
            max_call_depth: 100,
            max_table_elements: 1000,
            max_globals: 100,
            max_functions: 1000,
        }
    }
}

/// Memory region for sandboxed execution
#[derive(Debug)]
pub struct MemoryRegion {
    /// Base pointer
    base: *mut u8,
    /// Size in bytes
    size: u64,
    /// Whether region is readable
    readable: bool,
    /// Whether region is writable
    writable: bool,
    /// Whether region is executable
    executable: bool,
}

impl MemoryRegion {
    /// Check if address is within region
    pub fn contains(&self, address: u64, size: u64) -> bool {
        let base = self.base as u64;
        address >= base && address + size <= base + self.size
    }

    /// Check read permission
    pub fn can_read(&self) -> bool {
        self.readable
    }

    /// Check write permission
    pub fn can_write(&self) -> bool {
        self.writable
    }

    /// Check execute permission
    pub fn can_execute(&self) -> bool {
        self.executable
    }

    /// Get size
    pub fn size(&self) -> u64 {
        self.size
    }
}

// Safety: MemoryRegion is only accessed through safe interfaces
unsafe impl Send for MemoryRegion {}
unsafe impl Sync for MemoryRegion {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_config_defaults() {
        let config = MemoryConfig::default();
        assert_eq!(config.initial_bytes(), 16 * 65536); // 1MB
        assert_eq!(config.max_bytes(), 256 * 65536); // 16MB
    }

    #[test]
    fn test_memory_config_validation() {
        let mut config = MemoryConfig::default();
        assert!(config.validate().is_ok());

        config.initial_pages = 100;
        config.max_pages = 50;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_memory_limits_presets() {
        let default = MemoryLimits::default();
        let production = MemoryLimits::production();
        let ml = MemoryLimits::ml_workload();

        assert!(production.max_instance_memory > default.max_instance_memory);
        assert!(ml.max_instance_memory > production.max_instance_memory);
    }
}
