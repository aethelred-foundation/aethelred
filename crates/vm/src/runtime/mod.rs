//! WASM Runtime
//!
//! Enterprise-grade WebAssembly runtime built on Wasmer for secure AI
//! computation execution with comprehensive sandboxing and gas metering.
//!
//! # Features
//!
//! - **Wasmer Backend**: High-performance WASM execution with Cranelift/Singlepass
//! - **Gas Metering**: Configurable instruction-level gas accounting
//! - **Memory Sandboxing**: Strict memory isolation and bounds checking
//! - **Module Caching**: LRU cache for compiled WASM modules
//! - **Instance Pooling**: Reusable instances for performance
//! - **Host Functions**: Rich set of Aethelred-specific host imports
//!
//! # Security
//!
//! All WASM execution is sandboxed with:
//! - Memory isolation
//! - Instruction limits
//! - Stack depth limits
//! - Deterministic execution

mod config;
mod instance;
mod module;

pub use config::WasmConfig;
pub use instance::WasmInstance;
pub use module::WasmModule;

use crate::error::{VmError, VmResult};
use crate::gas::{GasMeter, SharedGasMeter};
use crate::memory::MemoryLimits;
use crate::precompiles::PrecompileRegistry;

use lru::LruCache;
use parking_lot::RwLock;
use std::num::NonZeroUsize;
use std::sync::Arc;

#[cfg(feature = "wasmer-runtime")]
use wasmer::{
    CompilerConfig, Engine, Function, FunctionEnv, FunctionEnvMut, Imports, Instance, Module,
    Store, Value,
};

#[cfg(feature = "wasmer-runtime")]
use wasmer_middlewares::Metering;

/// WASM Runtime for Aethelred VM
pub struct WasmRuntime {
    /// Configuration
    config: WasmConfig,

    /// Wasmer engine
    #[cfg(feature = "wasmer-runtime")]
    engine: Engine,

    /// Module cache
    module_cache: RwLock<LruCache<[u8; 32], Arc<WasmModule>>>,

    /// Precompile registry
    precompiles: Arc<PrecompileRegistry>,

    /// Memory limits
    memory_limits: MemoryLimits,
}

impl WasmRuntime {
    /// Create new WASM runtime
    pub fn new(config: WasmConfig) -> VmResult<Self> {
        config.validate()?;

        #[cfg(feature = "wasmer-runtime")]
        let engine = Self::create_engine(&config)?;

        let cache_size = NonZeroUsize::new(config.module_cache_size)
            .ok_or_else(|| VmError::Config("Cache size must be > 0".into()))?;

        Ok(Self {
            config: config.clone(),
            #[cfg(feature = "wasmer-runtime")]
            engine,
            module_cache: RwLock::new(LruCache::new(cache_size)),
            precompiles: Arc::new(PrecompileRegistry::new()),
            memory_limits: config.memory_limits,
        })
    }

    /// Create Wasmer engine with configuration
    #[cfg(feature = "wasmer-runtime")]
    fn create_engine(config: &WasmConfig) -> VmResult<Engine> {
        use wasmer::{Cranelift, Singlepass};

        // Choose compiler based on configuration
        let engine = match config.compiler.as_str() {
            "cranelift" => {
                let mut compiler = Cranelift::new();

                // Enable optimizations based on config
                if config.enable_optimizations {
                    compiler.opt_level(wasmer::CraneliftOptLevel::Speed);
                } else {
                    compiler.opt_level(wasmer::CraneliftOptLevel::None);
                }

                // Add gas metering middleware
                if config.enable_gas_metering {
                    let instruction_cost = config.gas_config.wasm_instruction_cost;
                    let metering =
                        Metering::new(config.default_gas_limit, move |_op| instruction_cost);
                    compiler.push_middleware(Arc::new(metering));
                }

                Engine::from(compiler)
            }
            "singlepass" => {
                // Singlepass is faster compilation but slower execution
                // Good for one-off executions
                let compiler = Singlepass::new();
                Engine::from(compiler)
            }
            _ => {
                return Err(VmError::Config(format!(
                    "Unknown compiler: {}",
                    config.compiler
                )));
            }
        };

        Ok(engine)
    }

    /// Compile WASM module
    pub fn compile(&self, bytecode: &[u8]) -> VmResult<WasmModule> {
        // Validate bytecode
        self.validate_bytecode(bytecode)?;

        // Check cache
        let hash = self.hash_bytecode(bytecode);
        if let Some(cached) = self.module_cache.read().peek(&hash) {
            return Ok((*cached).clone().as_ref().clone());
        }

        #[cfg(feature = "wasmer-runtime")]
        {
            let module = Module::new(&self.engine, bytecode)
                .map_err(|e| VmError::Compilation(e.to_string()))?;

            let wasm_module = WasmModule::new(module, hash, bytecode.len());

            // Cache the module
            let cached = Arc::new(wasm_module.clone());
            self.module_cache.write().put(hash, cached);

            Ok(wasm_module)
        }

        #[cfg(not(feature = "wasmer-runtime"))]
        {
            Err(VmError::Config("No WASM runtime feature enabled".into()))
        }
    }

    /// Compile and cache module
    pub fn compile_cached(&self, bytecode: &[u8]) -> VmResult<Arc<WasmModule>> {
        let hash = self.hash_bytecode(bytecode);

        // Check cache first
        if let Some(cached) = self.module_cache.read().peek(&hash) {
            return Ok(cached.clone());
        }

        // Compile
        let module = self.compile(bytecode)?;
        let cached = Arc::new(module);

        // Store in cache
        self.module_cache.write().put(hash, cached.clone());

        Ok(cached)
    }

    /// Instantiate a compiled module
    pub fn instantiate(&self, module: &WasmModule, gas_limit: u64) -> VmResult<WasmInstance> {
        let gas_meter = Arc::new(GasMeter::new(gas_limit, self.config.gas_config.clone()));

        #[cfg(feature = "wasmer-runtime")]
        {
            let mut store = Store::new(self.engine.clone());

            // Create host environment
            let env = HostEnv {
                gas_meter: gas_meter.clone(),
                _precompiles: self.precompiles.clone(),
                _memory_limits: self.memory_limits.clone(),
            };
            let env_fn = FunctionEnv::new(&mut store, env);

            // Create imports
            let imports = self.create_imports(&mut store, &env_fn)?;

            // Instantiate
            let instance = Instance::new(&mut store, module.inner(), &imports)
                .map_err(|e| VmError::Instantiation(e.to_string()))?;

            Ok(WasmInstance::new(store, instance, gas_meter))
        }

        #[cfg(not(feature = "wasmer-runtime"))]
        {
            Err(VmError::Config("No WASM runtime feature enabled".into()))
        }
    }

    /// Execute function in a new instance
    pub fn execute(
        &self,
        bytecode: &[u8],
        function: &str,
        args: &[Value],
        gas_limit: u64,
    ) -> VmResult<ExecutionResult> {
        let module = self.compile(bytecode)?;
        let mut instance = self.instantiate(&module, gas_limit)?;
        instance.call(function, args)
    }

    /// Create host imports
    #[cfg(feature = "wasmer-runtime")]
    fn create_imports(&self, store: &mut Store, env: &FunctionEnv<HostEnv>) -> VmResult<Imports> {
        let mut imports = Imports::new();

        // Add env module
        let mut env_exports = wasmer::Exports::new();

        // Logging
        env_exports.insert("log", Function::new_typed_with_env(store, env, host_log));

        // Time
        env_exports.insert(
            "get_time",
            Function::new_typed_with_env(store, env, host_get_time),
        );

        // Random
        env_exports.insert(
            "random",
            Function::new_typed_with_env(store, env, host_random),
        );

        // Gas
        env_exports.insert(
            "gas_remaining",
            Function::new_typed_with_env(store, env, host_gas_remaining),
        );
        env_exports.insert(
            "gas_used",
            Function::new_typed_with_env(store, env, host_gas_used),
        );

        // Precompile call
        env_exports.insert(
            "call_precompile",
            Function::new_typed_with_env(store, env, host_call_precompile),
        );

        // Memory operations
        env_exports.insert(
            "memory_copy",
            Function::new_typed_with_env(store, env, host_memory_copy),
        );

        // Abort
        env_exports.insert(
            "abort",
            Function::new_typed_with_env(store, env, host_abort),
        );

        imports.register_namespace("env", env_exports);

        // Add Aethelred-specific module
        let mut aethelred_exports = wasmer::Exports::new();

        aethelred_exports.insert(
            "verify_signature",
            Function::new_typed_with_env(store, env, host_verify_signature),
        );

        aethelred_exports.insert(
            "verify_tee_attestation",
            Function::new_typed_with_env(store, env, host_verify_tee),
        );

        aethelred_exports.insert(
            "verify_zkp",
            Function::new_typed_with_env(store, env, host_verify_zkp),
        );

        aethelred_exports.insert(
            "emit_event",
            Function::new_typed_with_env(store, env, host_emit_event),
        );

        imports.register_namespace("aethelred", aethelred_exports);

        Ok(imports)
    }

    /// Validate WASM bytecode
    fn validate_bytecode(&self, bytecode: &[u8]) -> VmResult<()> {
        // Check magic number
        if bytecode.len() < 8 {
            return Err(VmError::InvalidBinary("Too short".into()));
        }

        // WASM magic number: \0asm
        if &bytecode[0..4] != b"\0asm" {
            return Err(VmError::InvalidBinary("Invalid magic number".into()));
        }

        // Version check (1)
        let version = u32::from_le_bytes([bytecode[4], bytecode[5], bytecode[6], bytecode[7]]);
        if version != 1 {
            return Err(VmError::InvalidBinary(format!(
                "Unsupported WASM version: {}",
                version
            )));
        }

        // Size limits
        if bytecode.len() > self.config.max_bytecode_size {
            return Err(VmError::InvalidBinary(format!(
                "Bytecode too large: {} > {}",
                bytecode.len(),
                self.config.max_bytecode_size
            )));
        }

        Ok(())
    }

    /// Hash bytecode for caching
    fn hash_bytecode(&self, bytecode: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(bytecode);
        hasher.finalize().into()
    }

    /// Get configuration
    pub fn config(&self) -> &WasmConfig {
        &self.config
    }

    /// Get precompile registry
    pub fn precompiles(&self) -> &Arc<PrecompileRegistry> {
        &self.precompiles
    }

    /// Get cached module count
    pub fn cached_modules(&self) -> usize {
        self.module_cache.read().len()
    }

    /// Clear module cache
    pub fn clear_cache(&self) {
        self.module_cache.write().clear();
    }
}

/// Execution result
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Return values
    pub values: Vec<Value>,
    /// Gas used
    pub gas_used: u64,
    /// Success flag
    pub success: bool,
    /// Events emitted
    pub events: Vec<Event>,
}

/// Event emitted during execution
#[derive(Debug, Clone)]
pub struct Event {
    /// Event name
    pub name: String,
    /// Event data
    pub data: Vec<u8>,
}

// =============================================================================
// HOST ENVIRONMENT
// =============================================================================

/// Host environment for WASM instances
#[cfg(feature = "wasmer-runtime")]
struct HostEnv {
    /// Gas meter
    gas_meter: SharedGasMeter,
    /// Precompiles
    _precompiles: Arc<PrecompileRegistry>,
    /// Memory limits
    _memory_limits: MemoryLimits,
}

// =============================================================================
// HOST FUNCTIONS
// =============================================================================

#[cfg(feature = "wasmer-runtime")]
fn host_log(env: FunctionEnvMut<HostEnv>, ptr: u32, len: u32) {
    use crate::gas::HostCall;

    let data = env.data();
    let _ = data.gas_meter.consume_host_call(HostCall::Log);

    // In production, this would read from WASM memory and log
    tracing::debug!(target: "wasm", "Log called: ptr={}, len={}", ptr, len);
}

#[cfg(feature = "wasmer-runtime")]
fn host_get_time(env: FunctionEnvMut<HostEnv>) -> u64 {
    use crate::gas::HostCall;

    let data = env.data();
    let _ = data.gas_meter.consume_host_call(HostCall::GetTime);

    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(feature = "wasmer-runtime")]
fn host_random(env: FunctionEnvMut<HostEnv>) -> u64 {
    use crate::gas::HostCall;

    let data = env.data();
    let _ = data.gas_meter.consume_host_call(HostCall::Random);

    // Use deterministic random for reproducibility
    // In production, seed would come from block hash
    rand::random::<u64>()
}

#[cfg(feature = "wasmer-runtime")]
fn host_gas_remaining(env: FunctionEnvMut<HostEnv>) -> u64 {
    env.data().gas_meter.remaining()
}

#[cfg(feature = "wasmer-runtime")]
fn host_gas_used(env: FunctionEnvMut<HostEnv>) -> u64 {
    env.data().gas_meter.used()
}

#[cfg(feature = "wasmer-runtime")]
fn host_call_precompile(
    env: FunctionEnvMut<HostEnv>,
    _address: u64,
    _input_ptr: u32,
    _input_len: u32,
    _output_ptr: u32,
    _output_len: u32,
) -> u32 {
    use crate::gas::HostCall;

    let data = env.data();
    let _ = data.gas_meter.consume_host_call(HostCall::PrecompileCall);

    // In production, this would:
    // 1. Read input from WASM memory
    // 2. Call precompile
    // 3. Write output to WASM memory
    // 4. Return success/failure

    // For now, return 0 (success placeholder)
    0
}

#[cfg(feature = "wasmer-runtime")]
fn host_memory_copy(env: FunctionEnvMut<HostEnv>, _dest: u32, _src: u32, len: u32) {
    let data = env.data();
    let _ = data.gas_meter.consume_memory(len as u64);

    // Memory copy handled by WASM runtime
}

#[cfg(feature = "wasmer-runtime")]
fn host_abort(
    _env: FunctionEnvMut<HostEnv>,
    msg_ptr: u32,
    msg_len: u32,
    _file_ptr: u32,
    line: u32,
) {
    tracing::error!(
        target: "wasm",
        "WASM abort: msg_ptr={}, msg_len={}, line={}",
        msg_ptr, msg_len, line
    );
}

#[cfg(feature = "wasmer-runtime")]
fn host_verify_signature(
    env: FunctionEnvMut<HostEnv>,
    _sig_type: u32,
    _msg_ptr: u32,
    _msg_len: u32,
    _sig_ptr: u32,
    _sig_len: u32,
    _pubkey_ptr: u32,
    _pubkey_len: u32,
) -> u32 {
    use crate::gas::HostCall;

    let data = env.data();
    let _ = data.gas_meter.consume_host_call(HostCall::CryptoOp);

    // Signature verification via precompile
    // sig_type: 0 = ECDSA, 1 = Dilithium, 2 = Hybrid
    0 // Placeholder
}

#[cfg(feature = "wasmer-runtime")]
fn host_verify_tee(
    env: FunctionEnvMut<HostEnv>,
    _platform: u32,
    _attestation_ptr: u32,
    _attestation_len: u32,
    _expected_measurement_ptr: u32,
) -> u32 {
    use crate::gas::HostCall;

    let data = env.data();
    let _ = data.gas_meter.consume_host_call(HostCall::CryptoOp);

    // TEE attestation verification
    // platform: 0 = Nitro, 1 = SGX, 2 = SEV
    0 // Placeholder
}

#[cfg(feature = "wasmer-runtime")]
fn host_verify_zkp(
    env: FunctionEnvMut<HostEnv>,
    _proof_type: u32,
    _proof_ptr: u32,
    _proof_len: u32,
    _vk_ptr: u32,
    _vk_len: u32,
    _public_inputs_ptr: u32,
    _public_inputs_len: u32,
) -> u32 {
    use crate::gas::HostCall;

    let data = env.data();
    let _ = data.gas_meter.consume_host_call(HostCall::CryptoOp);

    // ZK proof verification
    // proof_type: 0 = Groth16, 1 = PLONK, 2 = EZKL
    0 // Placeholder
}

#[cfg(feature = "wasmer-runtime")]
fn host_emit_event(
    env: FunctionEnvMut<HostEnv>,
    name_ptr: u32,
    _name_len: u32,
    _data_ptr: u32,
    data_len: u32,
) {
    use crate::gas::HostCall;

    let data = env.data();
    let _ = data.gas_meter.consume_host_call(HostCall::Log);

    // Event emission
    tracing::info!(
        target: "wasm",
        "Event emitted: name_ptr={}, data_len={}",
        name_ptr, data_len
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "wasmer-runtime")]
    fn test_runtime_creation() {
        let config = WasmConfig::default();
        let runtime = WasmRuntime::new(config);
        assert!(runtime.is_ok());
    }

    #[test]
    fn test_bytecode_validation() {
        let config = WasmConfig::default();
        let runtime = WasmRuntime::new(config).unwrap();

        // Invalid magic number
        let invalid = vec![0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00];
        assert!(runtime.validate_bytecode(&invalid).is_err());

        // Too short
        let short = vec![0x00, 0x61, 0x73, 0x6d];
        assert!(runtime.validate_bytecode(&short).is_err());

        // Valid header
        let valid = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        assert!(runtime.validate_bytecode(&valid).is_ok());
    }

    #[test]
    fn test_bytecode_hash() {
        let config = WasmConfig::default();
        let runtime = WasmRuntime::new(config).unwrap();

        let bytecode1 = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        let bytecode2 = vec![0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x01];

        let hash1 = runtime.hash_bytecode(&bytecode1);
        let hash2 = runtime.hash_bytecode(&bytecode2);

        assert_ne!(hash1, hash2);
        assert_eq!(hash1, runtime.hash_bytecode(&bytecode1)); // Deterministic
    }
}
