// Package wasm implements the WASM virtual machine runtime for Aethelred
// This provides secure, sandboxed execution of smart contracts and compute workloads
package wasm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"time"
)

// RuntimeType defines the underlying WASM runtime
type RuntimeType string

const (
	// WasmerRuntime uses Wasmer for high-performance execution
	WasmerRuntime RuntimeType = "wasmer"
	// WasmtimeRuntime uses Wasmtime for security-focused execution
	WasmtimeRuntime RuntimeType = "wasmtime"
)

// GasConfig defines gas metering configuration
type GasConfig struct {
	// Base gas for function calls
	CallGas uint64

	// Gas per memory page (64KB)
	MemoryGasPerPage uint64

	// Gas per instruction (approximate)
	InstructionGas uint64

	// Gas for host function calls
	HostCallGas uint64

	// Maximum gas limit
	MaxGas uint64
}

// DefaultGasConfig returns default gas configuration
func DefaultGasConfig() *GasConfig {
	return &GasConfig{
		CallGas:          1000,
		MemoryGasPerPage: 4000,
		InstructionGas:   1,
		HostCallGas:      500,
		MaxGas:           10_000_000,
	}
}

// ModuleInstance represents a loaded WASM module
type ModuleInstance struct {
	// Module hash for identification
	Hash [32]byte

	// Module bytecode
	Bytecode []byte

	// Exported functions
	Exports map[string]FunctionInfo

	// Imported functions (host functions)
	Imports map[string]FunctionInfo

	// Memory configuration
	MemoryMin uint32 // Minimum memory pages
	MemoryMax uint32 // Maximum memory pages

	// Compiled module (runtime-specific)
	compiledModule interface{}
}

// FunctionInfo describes a WASM function
type FunctionInfo struct {
	Name       string
	ParamTypes []ValueType
	ResultTypes []ValueType
}

// ValueType represents WASM value types
type ValueType int

const (
	I32 ValueType = iota
	I64
	F32
	F64
	V128
	FuncRef
	ExternRef
)

// ExecutionResult contains the result of WASM execution
type ExecutionResult struct {
	// Return values from the function
	Returns []Value

	// Gas consumed
	GasUsed uint64

	// Execution time
	Duration time.Duration

	// Memory usage at completion
	MemoryUsed uint32

	// Logs emitted during execution
	Logs []string

	// State changes (for smart contracts)
	StateChanges []StateChange
}

// Value represents a WASM value
type Value struct {
	Type ValueType
	Data interface{}
}

// StateChange represents a state modification
type StateChange struct {
	Key   []byte
	Value []byte
}

// Runtime is the WASM execution runtime
type Runtime struct {
	mu sync.RWMutex

	// Runtime type
	runtimeType RuntimeType

	// Gas configuration
	gasConfig *GasConfig

	// Loaded modules
	modules map[[32]byte]*ModuleInstance

	// Host functions registry
	hostFunctions map[string]HostFunction

	// State store for smart contracts
	stateStore StateStore

	// Execution context pool
	contextPool sync.Pool
}

// HostFunction is a function provided by the host
type HostFunction func(ctx *ExecutionContext, args []Value) ([]Value, error)

// StateStore provides persistent state storage
type StateStore interface {
	Get(key []byte) ([]byte, error)
	Set(key, value []byte) error
	Delete(key []byte) error
	Has(key []byte) (bool, error)
}

// ExecutionContext provides context for WASM execution
type ExecutionContext struct {
	// Parent context for cancellation
	ctx context.Context

	// Gas remaining
	gasRemaining uint64

	// Memory instance
	memory []byte
	memoryPages uint32
	memoryMax   uint32

	// State changes accumulated
	stateChanges []StateChange

	// Logs accumulated
	logs []string

	// Host functions available
	hostFunctions map[string]HostFunction

	// State store
	stateStore StateStore

	// Start time
	startTime time.Time

	// Timeout
	timeout time.Duration
}

// NewRuntime creates a new WASM runtime
func NewRuntime(runtimeType RuntimeType, gasConfig *GasConfig) *Runtime {
	if gasConfig == nil {
		gasConfig = DefaultGasConfig()
	}

	return &Runtime{
		runtimeType:   runtimeType,
		gasConfig:     gasConfig,
		modules:       make(map[[32]byte]*ModuleInstance),
		hostFunctions: make(map[string]HostFunction),
		contextPool: sync.Pool{
			New: func() interface{} {
				return &ExecutionContext{
					logs:         make([]string, 0, 16),
					stateChanges: make([]StateChange, 0, 16),
				}
			},
		},
	}
}

// SetStateStore sets the state store for smart contract execution
func (r *Runtime) SetStateStore(store StateStore) {
	r.stateStore = store
}

// RegisterHostFunction registers a host function
func (r *Runtime) RegisterHostFunction(name string, fn HostFunction) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hostFunctions[name] = fn
}

// LoadModule loads a WASM module
func (r *Runtime) LoadModule(bytecode []byte) (*ModuleInstance, error) {
	// Validate WASM magic number
	if len(bytecode) < 8 {
		return nil, errors.New("bytecode too short")
	}
	if bytecode[0] != 0x00 || bytecode[1] != 0x61 || bytecode[2] != 0x73 || bytecode[3] != 0x6d {
		return nil, errors.New("invalid WASM magic number")
	}

	// Calculate module hash
	hash := sha256.Sum256(bytecode)

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check if already loaded
	if module, exists := r.modules[hash]; exists {
		return module, nil
	}

	// Parse module (simplified - in production, use actual WASM parser)
	module := &ModuleInstance{
		Hash:     hash,
		Bytecode: bytecode,
		Exports:  make(map[string]FunctionInfo),
		Imports:  make(map[string]FunctionInfo),
		MemoryMin: 1,
		MemoryMax: 256, // 16MB max
	}

	// Compile module (placeholder - in production, use Wasmer/Wasmtime)
	module.compiledModule = bytecode

	r.modules[hash] = module
	return module, nil
}

// Execute executes a function in a loaded module
func (r *Runtime) Execute(
	ctx context.Context,
	moduleHash [32]byte,
	functionName string,
	args []Value,
	gasLimit uint64,
	timeout time.Duration,
) (*ExecutionResult, error) {
	r.mu.RLock()
	module, exists := r.modules[moduleHash]
	hostFunctions := r.hostFunctions
	r.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("module not found: %x", moduleHash)
	}

	// Get execution context from pool
	execCtx := r.contextPool.Get().(*ExecutionContext)
	defer func() {
		// Reset and return to pool
		execCtx.logs = execCtx.logs[:0]
		execCtx.stateChanges = execCtx.stateChanges[:0]
		execCtx.memory = nil
		r.contextPool.Put(execCtx)
	}()

	// Initialize execution context
	execCtx.ctx = ctx
	execCtx.gasRemaining = gasLimit
	execCtx.memory = make([]byte, module.MemoryMin*65536) // 64KB per page
	execCtx.memoryPages = module.MemoryMin
	execCtx.memoryMax = module.MemoryMax
	execCtx.hostFunctions = hostFunctions
	execCtx.stateStore = r.stateStore
	execCtx.startTime = time.Now()
	execCtx.timeout = timeout

	// Charge gas for function call
	if !execCtx.consumeGas(r.gasConfig.CallGas) {
		return nil, errors.New("out of gas")
	}

	// Execute function (placeholder - in production, use actual WASM execution)
	result, err := r.executeFunction(execCtx, module, functionName, args)
	if err != nil {
		return nil, err
	}

	return &ExecutionResult{
		Returns:      result,
		GasUsed:      gasLimit - execCtx.gasRemaining,
		Duration:     time.Since(execCtx.startTime),
		MemoryUsed:   execCtx.memoryPages * 65536,
		Logs:         append([]string(nil), execCtx.logs...),
		StateChanges: append([]StateChange(nil), execCtx.stateChanges...),
	}, nil
}

// executeFunction executes a WASM function (placeholder implementation)
func (r *Runtime) executeFunction(
	ctx *ExecutionContext,
	module *ModuleInstance,
	functionName string,
	args []Value,
) ([]Value, error) {
	// Check timeout
	select {
	case <-ctx.ctx.Done():
		return nil, ctx.ctx.Err()
	default:
	}

	// Check timeout
	if ctx.timeout > 0 && time.Since(ctx.startTime) > ctx.timeout {
		return nil, errors.New("execution timeout")
	}

	// Placeholder execution
	// In production, this would:
	// 1. Look up function in exports
	// 2. Set up the call frame
	// 3. Execute WASM instructions
	// 4. Handle traps and exceptions
	// 5. Return results

	// Simulate some gas consumption
	if !ctx.consumeGas(1000) {
		return nil, errors.New("out of gas")
	}

	// Return placeholder result
	return []Value{{Type: I64, Data: int64(0)}}, nil
}

// consumeGas attempts to consume gas, returns false if insufficient
func (ctx *ExecutionContext) consumeGas(amount uint64) bool {
	if ctx.gasRemaining < amount {
		return false
	}
	ctx.gasRemaining -= amount
	return true
}

// Log adds a log entry
func (ctx *ExecutionContext) Log(message string) {
	ctx.logs = append(ctx.logs, message)
}

// SetState sets a state value
func (ctx *ExecutionContext) SetState(key, value []byte) error {
	ctx.stateChanges = append(ctx.stateChanges, StateChange{
		Key:   append([]byte(nil), key...),
		Value: append([]byte(nil), value...),
	})
	return nil
}

// GetState gets a state value
func (ctx *ExecutionContext) GetState(key []byte) ([]byte, error) {
	if ctx.stateStore == nil {
		return nil, errors.New("no state store configured")
	}
	return ctx.stateStore.Get(key)
}

// GrowMemory grows memory by the specified number of pages
func (ctx *ExecutionContext) GrowMemory(pages uint32) bool {
	newPages := ctx.memoryPages + pages
	if newPages > ctx.memoryMax {
		return false
	}

	newMemory := make([]byte, newPages*65536)
	copy(newMemory, ctx.memory)
	ctx.memory = newMemory
	ctx.memoryPages = newPages
	return true
}

// ReadMemory reads from WASM memory
func (ctx *ExecutionContext) ReadMemory(offset, length uint32) ([]byte, error) {
	if uint64(offset)+uint64(length) > uint64(len(ctx.memory)) {
		return nil, errors.New("memory access out of bounds")
	}
	result := make([]byte, length)
	copy(result, ctx.memory[offset:offset+length])
	return result, nil
}

// WriteMemory writes to WASM memory
func (ctx *ExecutionContext) WriteMemory(offset uint32, data []byte) error {
	if uint64(offset)+uint64(len(data)) > uint64(len(ctx.memory)) {
		return errors.New("memory access out of bounds")
	}
	copy(ctx.memory[offset:], data)
	return nil
}

// StandardHostFunctions returns the standard Aethelred host functions
func StandardHostFunctions() map[string]HostFunction {
	return map[string]HostFunction{
		// Logging
		"env.log": func(ctx *ExecutionContext, args []Value) ([]Value, error) {
			if len(args) < 2 {
				return nil, errors.New("log requires ptr and len arguments")
			}
			ptr := args[0].Data.(int32)
			length := args[1].Data.(int32)
			data, err := ctx.ReadMemory(uint32(ptr), uint32(length))
			if err != nil {
				return nil, err
			}
			ctx.Log(string(data))
			return nil, nil
		},

		// State access
		"env.state_get": func(ctx *ExecutionContext, args []Value) ([]Value, error) {
			if len(args) < 4 {
				return nil, errors.New("state_get requires key_ptr, key_len, val_ptr, val_len")
			}
			keyPtr := args[0].Data.(int32)
			keyLen := args[1].Data.(int32)
			valPtr := args[2].Data.(int32)
			valLen := args[3].Data.(int32)

			key, err := ctx.ReadMemory(uint32(keyPtr), uint32(keyLen))
			if err != nil {
				return nil, err
			}

			value, err := ctx.GetState(key)
			if err != nil {
				return []Value{{Type: I32, Data: int32(-1)}}, nil
			}

			if len(value) > int(valLen) {
				return []Value{{Type: I32, Data: int32(-2)}}, nil // Buffer too small
			}

			if err := ctx.WriteMemory(uint32(valPtr), value); err != nil {
				return nil, err
			}

			return []Value{{Type: I32, Data: int32(len(value))}}, nil
		},

		"env.state_set": func(ctx *ExecutionContext, args []Value) ([]Value, error) {
			if len(args) < 4 {
				return nil, errors.New("state_set requires key_ptr, key_len, val_ptr, val_len")
			}
			keyPtr := args[0].Data.(int32)
			keyLen := args[1].Data.(int32)
			valPtr := args[2].Data.(int32)
			valLen := args[3].Data.(int32)

			key, err := ctx.ReadMemory(uint32(keyPtr), uint32(keyLen))
			if err != nil {
				return nil, err
			}

			value, err := ctx.ReadMemory(uint32(valPtr), uint32(valLen))
			if err != nil {
				return nil, err
			}

			if err := ctx.SetState(key, value); err != nil {
				return []Value{{Type: I32, Data: int32(-1)}}, nil
			}

			return []Value{{Type: I32, Data: int32(0)}}, nil
		},

		// Cryptographic functions
		"env.sha256": func(ctx *ExecutionContext, args []Value) ([]Value, error) {
			if len(args) < 3 {
				return nil, errors.New("sha256 requires input_ptr, input_len, output_ptr")
			}
			inputPtr := args[0].Data.(int32)
			inputLen := args[1].Data.(int32)
			outputPtr := args[2].Data.(int32)

			input, err := ctx.ReadMemory(uint32(inputPtr), uint32(inputLen))
			if err != nil {
				return nil, err
			}

			hash := sha256.Sum256(input)
			if err := ctx.WriteMemory(uint32(outputPtr), hash[:]); err != nil {
				return nil, err
			}

			return nil, nil
		},

		// Gas tracking
		"env.gas_remaining": func(ctx *ExecutionContext, args []Value) ([]Value, error) {
			return []Value{{Type: I64, Data: int64(ctx.gasRemaining)}}, nil
		},
	}
}

// UnloadModule removes a module from the runtime
func (r *Runtime) UnloadModule(hash [32]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.modules, hash)
}

// GetLoadedModules returns all loaded module hashes
func (r *Runtime) GetLoadedModules() [][32]byte {
	r.mu.RLock()
	defer r.mu.RUnlock()

	hashes := make([][32]byte, 0, len(r.modules))
	for hash := range r.modules {
		hashes = append(hashes, hash)
	}
	return hashes
}
