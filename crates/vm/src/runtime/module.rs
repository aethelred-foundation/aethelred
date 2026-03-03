//! WASM Module
//!
//! Compiled WASM module wrapper with metadata.

use serde::{Deserialize, Serialize};

#[cfg(feature = "wasmer-runtime")]
use wasmer::Module;

/// Compiled WASM module
#[derive(Clone)]
pub struct WasmModule {
    /// Wasmer module
    #[cfg(feature = "wasmer-runtime")]
    module: Module,

    /// Module hash (SHA-256 of bytecode)
    hash: [u8; 32],

    /// Original bytecode size
    bytecode_size: usize,

    /// Exported functions
    exports: Vec<ExportInfo>,

    /// Imported functions
    imports: Vec<ImportInfo>,

    /// Memory requirements
    memory_requirements: MemoryRequirements,
}

impl WasmModule {
    /// Create new module wrapper
    #[cfg(feature = "wasmer-runtime")]
    pub fn new(module: Module, hash: [u8; 32], bytecode_size: usize) -> Self {
        // Extract exports
        let exports = module
            .exports()
            .filter_map(|e| {
                if let wasmer::ExternType::Function(ft) = e.ty() {
                    Some(ExportInfo {
                        name: e.name().to_string(),
                        kind: ExportKind::Function,
                        params: ft.params().iter().map(|t| format!("{:?}", t)).collect(),
                        returns: ft.results().iter().map(|t| format!("{:?}", t)).collect(),
                    })
                } else {
                    None
                }
            })
            .collect();

        // Extract imports
        let imports = module
            .imports()
            .filter_map(|i| {
                Some(ImportInfo {
                    module: i.module().to_string(),
                    name: i.name().to_string(),
                    kind: match i.ty() {
                        wasmer::ExternType::Function(_) => ImportKind::Function,
                        wasmer::ExternType::Memory(_) => ImportKind::Memory,
                        wasmer::ExternType::Global(_) => ImportKind::Global,
                        wasmer::ExternType::Table(_) => ImportKind::Table,
                    },
                })
            })
            .collect();

        // Memory requirements (simplified)
        let memory_requirements = MemoryRequirements {
            initial_pages: 1,
            max_pages: Some(256),
        };

        Self {
            module,
            hash,
            bytecode_size,
            exports,
            imports,
            memory_requirements,
        }
    }

    /// Get inner wasmer module
    #[cfg(feature = "wasmer-runtime")]
    pub fn inner(&self) -> &Module {
        &self.module
    }

    /// Get module hash
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Get hash as hex string
    pub fn hash_hex(&self) -> String {
        hex::encode(self.hash)
    }

    /// Get bytecode size
    pub fn bytecode_size(&self) -> usize {
        self.bytecode_size
    }

    /// Get exports
    pub fn exports(&self) -> &[ExportInfo] {
        &self.exports
    }

    /// Get imports
    pub fn imports(&self) -> &[ImportInfo] {
        &self.imports
    }

    /// Check if function is exported
    pub fn has_export(&self, name: &str) -> bool {
        self.exports.iter().any(|e| e.name == name)
    }

    /// Get memory requirements
    pub fn memory_requirements(&self) -> &MemoryRequirements {
        &self.memory_requirements
    }

    /// Get function signature
    pub fn function_signature(&self, name: &str) -> Option<&ExportInfo> {
        self.exports
            .iter()
            .find(|e| e.name == name && e.kind == ExportKind::Function)
    }
}

impl std::fmt::Debug for WasmModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmModule")
            .field("hash", &self.hash_hex())
            .field("bytecode_size", &self.bytecode_size)
            .field("exports", &self.exports.len())
            .field("imports", &self.imports.len())
            .finish()
    }
}

/// Export information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportInfo {
    /// Export name
    pub name: String,
    /// Export kind
    pub kind: ExportKind,
    /// Parameter types (for functions)
    pub params: Vec<String>,
    /// Return types (for functions)
    pub returns: Vec<String>,
}

/// Export kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExportKind {
    Function,
    Memory,
    Global,
    Table,
}

/// Import information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportInfo {
    /// Module name
    pub module: String,
    /// Import name
    pub name: String,
    /// Import kind
    pub kind: ImportKind,
}

/// Import kind
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImportKind {
    Function,
    Memory,
    Global,
    Table,
}

/// Memory requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryRequirements {
    /// Initial memory pages
    pub initial_pages: u32,
    /// Maximum memory pages (None = unlimited)
    pub max_pages: Option<u32>,
}

impl MemoryRequirements {
    /// Get initial memory in bytes
    pub fn initial_bytes(&self) -> u64 {
        self.initial_pages as u64 * 65536
    }

    /// Get maximum memory in bytes
    pub fn max_bytes(&self) -> Option<u64> {
        self.max_pages.map(|p| p as u64 * 65536)
    }
}

/// Module metadata for on-chain storage
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModuleMetadata {
    /// Module hash
    pub hash: [u8; 32],
    /// Bytecode size
    pub bytecode_size: usize,
    /// Exported functions
    pub exports: Vec<String>,
    /// Required imports (module.name)
    pub imports: Vec<String>,
    /// Initial memory pages
    pub initial_memory_pages: u32,
    /// Maximum memory pages
    pub max_memory_pages: Option<u32>,
    /// Deployment timestamp
    pub deployed_at: u64,
    /// Deployer address
    pub deployer: Option<Vec<u8>>,
}

#[allow(dead_code)]
impl ModuleMetadata {
    /// Create from WasmModule
    pub fn from_module(module: &WasmModule) -> Self {
        Self {
            hash: module.hash,
            bytecode_size: module.bytecode_size,
            exports: module
                .exports
                .iter()
                .filter(|e| e.kind == ExportKind::Function)
                .map(|e| e.name.clone())
                .collect(),
            imports: module
                .imports
                .iter()
                .map(|i| format!("{}.{}", i.module, i.name))
                .collect(),
            initial_memory_pages: module.memory_requirements.initial_pages,
            max_memory_pages: module.memory_requirements.max_pages,
            deployed_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            deployer: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_requirements() {
        let req = MemoryRequirements {
            initial_pages: 1,
            max_pages: Some(256),
        };

        assert_eq!(req.initial_bytes(), 65536);
        assert_eq!(req.max_bytes(), Some(256 * 65536));
    }

    #[test]
    fn test_export_kind() {
        assert_eq!(ExportKind::Function, ExportKind::Function);
        assert_ne!(ExportKind::Function, ExportKind::Memory);
    }
}
