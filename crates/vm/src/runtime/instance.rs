//! WASM Instance
//!
//! Instantiated WASM module with execution capabilities.

use crate::error::{VmError, VmResult};
use crate::gas::SharedGasMeter;
use crate::runtime::ExecutionResult;

#[cfg(feature = "wasmer-runtime")]
use wasmer::{Instance, Memory, Store, TypedFunction, Value, WasmTypeList};

/// WASM Instance for execution
pub struct WasmInstance {
    /// Wasmer store
    #[cfg(feature = "wasmer-runtime")]
    store: Store,

    /// Wasmer instance
    #[cfg(feature = "wasmer-runtime")]
    instance: Instance,

    /// Gas meter
    gas_meter: SharedGasMeter,

    /// Events collected during execution
    events: Vec<crate::runtime::Event>,
}

impl WasmInstance {
    /// Create new instance
    #[cfg(feature = "wasmer-runtime")]
    pub fn new(store: Store, instance: Instance, gas_meter: SharedGasMeter) -> Self {
        Self {
            store,
            instance,
            gas_meter,
            events: Vec::new(),
        }
    }

    /// Call exported function
    #[cfg(feature = "wasmer-runtime")]
    pub fn call(&mut self, name: &str, args: &[Value]) -> VmResult<ExecutionResult> {
        // Get function
        let func = self
            .instance
            .exports
            .get_function(name)
            .map_err(|e| VmError::FunctionNotFound(format!("{}: {}", name, e)))?;

        // Execute
        let result = func
            .call(&mut self.store, args)
            .map_err(|e| VmError::Execution(e.to_string()))?;

        Ok(ExecutionResult {
            values: result.to_vec(),
            gas_used: self.gas_meter.used(),
            success: true,
            events: std::mem::take(&mut self.events),
        })
    }

    /// Call typed function (more efficient)
    #[cfg(feature = "wasmer-runtime")]
    pub fn call_typed<Params, Results>(
        &mut self,
        name: &str,
    ) -> VmResult<TypedFunction<Params, Results>>
    where
        Params: WasmTypeList,
        Results: WasmTypeList,
    {
        self.instance
            .exports
            .get_typed_function(&self.store, name)
            .map_err(|e| VmError::FunctionNotFound(format!("{}: {}", name, e)))
    }

    /// Read from instance memory
    #[cfg(feature = "wasmer-runtime")]
    pub fn read_memory(&self, offset: u64, length: u64) -> VmResult<Vec<u8>> {
        let memory = self.get_memory()?;
        let view = memory.view(&self.store);

        if offset + length > view.data_size() {
            return Err(VmError::MemoryViolation {
                address: offset,
                size: length,
            });
        }

        let mut buffer = vec![0u8; length as usize];
        view.read(offset, &mut buffer)
            .map_err(|e| VmError::Internal(format!("Memory read failed: {}", e)))?;

        Ok(buffer)
    }

    /// Write to instance memory
    #[cfg(feature = "wasmer-runtime")]
    pub fn write_memory(&mut self, offset: u64, data: &[u8]) -> VmResult<()> {
        let memory = self.get_memory()?;
        let view = memory.view(&self.store);

        if offset + data.len() as u64 > view.data_size() {
            return Err(VmError::MemoryViolation {
                address: offset,
                size: data.len() as u64,
            });
        }

        view.write(offset, data)
            .map_err(|e| VmError::Internal(format!("Memory write failed: {}", e)))?;

        Ok(())
    }

    /// Get memory export
    #[cfg(feature = "wasmer-runtime")]
    fn get_memory(&self) -> VmResult<Memory> {
        self.instance
            .exports
            .get_memory("memory")
            .cloned()
            .map_err(|_| VmError::Export("Memory export 'memory' not found".into()))
    }

    /// Get memory size in pages
    #[cfg(feature = "wasmer-runtime")]
    pub fn memory_pages(&self) -> VmResult<u32> {
        let memory = self.get_memory()?;
        Ok(memory.view(&self.store).size().0)
    }

    /// Get memory size in bytes
    #[cfg(feature = "wasmer-runtime")]
    pub fn memory_bytes(&self) -> VmResult<u64> {
        Ok(self.memory_pages()? as u64 * 65536)
    }

    /// Grow memory
    #[cfg(feature = "wasmer-runtime")]
    pub fn grow_memory(&mut self, pages: u32) -> VmResult<u32> {
        let memory = self.get_memory()?;
        let old_pages =
            memory
                .grow(&mut self.store, pages)
                .map_err(|_| VmError::MemoryLimitExceeded {
                    requested: pages,
                    max: 0, // Unknown from error
                })?;
        Ok(old_pages.0)
    }

    /// Get gas meter
    pub fn gas_meter(&self) -> &SharedGasMeter {
        &self.gas_meter
    }

    /// Get gas used
    pub fn gas_used(&self) -> u64 {
        self.gas_meter.used()
    }

    /// Get gas remaining
    pub fn gas_remaining(&self) -> u64 {
        self.gas_meter.remaining()
    }

    /// Add event
    pub fn emit_event(&mut self, name: String, data: Vec<u8>) {
        self.events.push(crate::runtime::Event { name, data });
    }

    /// Get events
    pub fn events(&self) -> &[crate::runtime::Event] {
        &self.events
    }

    /// Check if instance has function
    #[cfg(feature = "wasmer-runtime")]
    pub fn has_function(&self, name: &str) -> bool {
        self.instance.exports.get_function(name).is_ok()
    }

    /// Get all exported function names
    #[cfg(feature = "wasmer-runtime")]
    pub fn exported_functions(&self) -> Vec<String> {
        self.instance
            .exports
            .iter()
            .filter_map(|(name, export)| {
                if matches!(export, wasmer::Extern::Function(_)) {
                    Some(name.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get global value
    #[cfg(feature = "wasmer-runtime")]
    pub fn get_global(&mut self, name: &str) -> VmResult<Value> {
        let global = self
            .instance
            .exports
            .get_global(name)
            .map_err(|e| VmError::Export(format!("Global '{}' not found: {}", name, e)))?;
        Ok(global.get(&mut self.store))
    }

    /// Set global value
    #[cfg(feature = "wasmer-runtime")]
    pub fn set_global(&mut self, name: &str, value: Value) -> VmResult<()> {
        let global = self
            .instance
            .exports
            .get_global(name)
            .map_err(|e| VmError::Export(format!("Global '{}' not found: {}", name, e)))?;
        global
            .set(&mut self.store, value)
            .map_err(|e| VmError::Internal(format!("Failed to set global: {}", e)))?;
        Ok(())
    }
}

impl std::fmt::Debug for WasmInstance {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WasmInstance")
            .field("gas_used", &self.gas_meter.used())
            .field("gas_remaining", &self.gas_meter.remaining())
            .field("events", &self.events.len())
            .finish()
    }
}

/// Instance pool for reusing warm instances
#[allow(dead_code)]
pub struct InstancePool {
    /// Pool of available instances
    pool: parking_lot::Mutex<Vec<WasmInstance>>,
    /// Maximum pool size
    max_size: usize,
}

#[allow(dead_code)]
impl InstancePool {
    /// Create new pool
    pub fn new(max_size: usize) -> Self {
        Self {
            pool: parking_lot::Mutex::new(Vec::with_capacity(max_size)),
            max_size,
        }
    }

    /// Get instance from pool
    pub fn get(&self) -> Option<WasmInstance> {
        self.pool.lock().pop()
    }

    /// Return instance to pool
    pub fn put(&self, instance: WasmInstance) {
        let mut pool = self.pool.lock();
        if pool.len() < self.max_size {
            pool.push(instance);
        }
        // Otherwise, instance is dropped
    }

    /// Pool size
    pub fn len(&self) -> usize {
        self.pool.lock().len()
    }

    /// Check if pool is empty
    pub fn is_empty(&self) -> bool {
        self.pool.lock().is_empty()
    }

    /// Clear pool
    pub fn clear(&self) {
        self.pool.lock().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instance_pool() {
        let pool: InstancePool = InstancePool::new(10);

        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert!(pool.get().is_none());
    }
}
