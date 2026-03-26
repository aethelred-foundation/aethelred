#![no_main]
//! Fuzz target for WASM bytecode compilation and VM configuration.
//!
//! Feeds arbitrary byte slices to the Aethelred WasmRuntime compiler to
//! ensure that malformed or adversarial WASM modules never cause panics,
//! buffer overflows, or undefined behaviour. Also fuzzes WasmConfig
//! validation, GasMeter operations, and MemoryConfig validation with
//! random parameters.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 {
        return;
    }

    // -----------------------------------------------------------------------
    // 1. Fuzz WASM bytecode compilation
    // -----------------------------------------------------------------------
    // The compile path must gracefully reject invalid bytecode with an error,
    // never panic. Use a testing config to keep compilation lightweight.
    {
        let config = aethelred_vm::WasmConfig::testing();
        if let Ok(runtime) = aethelred_vm::WasmRuntime::new(config) {
            // Must return Err for invalid bytecode, never panic.
            let _ = runtime.compile(data);
        }
    }

    // -----------------------------------------------------------------------
    // 2. Fuzz WasmConfig validation with arbitrary field values
    // -----------------------------------------------------------------------
    {
        if data.len() >= 24 {
            let max_bytecode_size = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
            let max_execution_time_ms = u64::from_le_bytes(data[4..12].try_into().unwrap());
            let max_call_depth = u32::from_le_bytes(data[12..16].try_into().unwrap());
            let initial_pages = u16::from_le_bytes(data[16..18].try_into().unwrap()) as u32;
            let max_pages = u16::from_le_bytes(data[18..20].try_into().unwrap()) as u32;
            let default_gas_limit = u32::from_le_bytes(data[20..24].try_into().unwrap()) as u64;

            let compiler = if data[0] % 3 == 0 {
                "cranelift"
            } else if data[0] % 3 == 1 {
                "singlepass"
            } else {
                "invalid"
            };

            let config = aethelred_vm::WasmConfig {
                compiler: compiler.to_string(),
                enable_optimizations: data[1] % 2 == 0,
                enable_gas_metering: data[2] % 2 == 0,
                max_bytecode_size,
                max_execution_time_ms,
                max_call_depth,
                max_stack_size: (data[3] as u64 + 1) * 1024,
                memory_limits: aethelred_vm::MemoryLimits::testing(),
                initial_memory_pages: initial_pages,
                max_memory_pages: max_pages,
                gas_config: aethelred_vm::GasConfig::testing(),
                default_gas_limit,
                enable_caching: data[4] % 2 == 0,
                module_cache_size: (data[5] as usize) + 1,
                enable_simd: false,
                enable_threads: false,
                enable_reference_types: false,
                enable_bulk_memory: false,
                enable_multi_value: false,
                deterministic: true,
                strict_validation: true,
                bounds_checking: true,
            };

            // validate() must never panic, only return Ok/Err.
            let _ = config.validate();
        }
    }

    // -----------------------------------------------------------------------
    // 3. Fuzz GasMeter consume/remaining/reset with arbitrary amounts
    // -----------------------------------------------------------------------
    {
        if data.len() >= 16 {
            let limit = u64::from_le_bytes(data[0..8].try_into().unwrap());
            // Avoid zero limit causing issues
            let limit = limit.saturating_add(1);

            let meter = aethelred_vm::GasMeter::with_limit(limit);

            // Issue a series of consume calls derived from the fuzz input.
            let mut offset = 8;
            while offset + 8 <= data.len() {
                let amount = u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap());
                let _ = meter.consume(amount);
                offset += 8;
            }

            // These accessors must always be safe.
            let _ = meter.used();
            let _ = meter.remaining();
            let _ = meter.is_exhausted();
            let _ = meter.limit();

            // Reset and verify consistency.
            meter.reset();
            assert_eq!(meter.used(), 0);
            assert_eq!(meter.remaining(), limit);
        }
    }

    // -----------------------------------------------------------------------
    // 4. Fuzz MemoryConfig validation with edge-case page values
    // -----------------------------------------------------------------------
    {
        if data.len() >= 12 {
            let initial_pages = u32::from_le_bytes(data[0..4].try_into().unwrap());
            let max_pages = u32::from_le_bytes(data[4..8].try_into().unwrap());
            let stack_size = u32::from_le_bytes(data[8..12].try_into().unwrap()) as u64;

            let config = aethelred_vm::MemoryConfig {
                initial_pages,
                max_pages,
                bounds_checking: data[0] % 2 == 0,
                zero_on_alloc: data[1] % 2 == 0,
                guard_pages: data[2] % 2 == 0,
                stack_size,
            };

            // validate() must never panic.
            let _ = config.validate();

            // Accessor methods must never panic.
            let _ = config.initial_bytes();
            let _ = config.max_bytes();
        }
    }

    // -----------------------------------------------------------------------
    // 5. Fuzz GasConfig cost calculations with arbitrary WasmOp inputs
    // -----------------------------------------------------------------------
    {
        let gas_config = aethelred_vm::GasConfig::default();

        // Exercise wasm_cost with a variety of ops — must never panic.
        use aethelred_vm::gas::{HostCall, WasmOp};
        let ops = [
            WasmOp::Unreachable, WasmOp::Nop, WasmOp::Block, WasmOp::Loop,
            WasmOp::If, WasmOp::Br, WasmOp::BrIf, WasmOp::BrTable,
            WasmOp::Return, WasmOp::Call, WasmOp::CallIndirect,
            WasmOp::I32Const, WasmOp::I64Const, WasmOp::F32Const, WasmOp::F64Const,
            WasmOp::LocalGet, WasmOp::LocalSet, WasmOp::GlobalGet, WasmOp::GlobalSet,
            WasmOp::I32Load, WasmOp::I64Load, WasmOp::I32Store, WasmOp::I64Store,
            WasmOp::MemorySize, WasmOp::MemoryGrow,
            WasmOp::I32Add, WasmOp::I32Sub, WasmOp::I32Mul,
            WasmOp::I32DivS, WasmOp::I32DivU, WasmOp::I32RemS, WasmOp::I32RemU,
            WasmOp::I64Add, WasmOp::I64Sub, WasmOp::I64Mul,
            WasmOp::I64DivS, WasmOp::I64DivU, WasmOp::I64RemS, WasmOp::I64RemU,
            WasmOp::I32And, WasmOp::I32Or, WasmOp::I32Xor,
            WasmOp::I64And, WasmOp::I64Or, WasmOp::I64Xor,
            WasmOp::F32Add, WasmOp::F32Sub, WasmOp::F32Mul, WasmOp::F32Div, WasmOp::F32Sqrt,
            WasmOp::F64Add, WasmOp::F64Sub, WasmOp::F64Mul, WasmOp::F64Div, WasmOp::F64Sqrt,
            WasmOp::I32Eqz, WasmOp::I32Eq, WasmOp::I32Ne,
            WasmOp::I32WrapI64, WasmOp::I64ExtendI32S,
            WasmOp::Other,
        ];

        for op in &ops {
            let _ = gas_config.wasm_cost(*op);
        }

        // Fuzz memory_cost with arbitrary byte count.
        if data.len() >= 8 {
            let bytes = u64::from_le_bytes(data[0..8].try_into().unwrap());
            let _ = gas_config.memory_cost(bytes);
        }

        // Fuzz host_cost.
        let calls = [
            HostCall::Log, HostCall::GetTime, HostCall::Random,
            HostCall::StorageRead, HostCall::StorageWrite,
            HostCall::PrecompileCall, HostCall::CryptoOp,
            HostCall::NetworkOp, HostCall::Other,
        ];
        for call in &calls {
            let _ = gas_config.host_cost(*call);
        }
    }
});
