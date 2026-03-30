package wasm

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestDefaultGasConfig(t *testing.T) {
	t.Parallel()
	gc := DefaultGasConfig()
	if gc.CallGas != 1000 {
		t.Errorf("expected CallGas=1000, got %d", gc.CallGas)
	}
	if gc.MemoryGasPerPage != 4000 {
		t.Errorf("expected MemoryGasPerPage=4000, got %d", gc.MemoryGasPerPage)
	}
	if gc.InstructionGas != 1 {
		t.Errorf("expected InstructionGas=1, got %d", gc.InstructionGas)
	}
	if gc.HostCallGas != 500 {
		t.Errorf("expected HostCallGas=500, got %d", gc.HostCallGas)
	}
	if gc.MaxGas != 10_000_000 {
		t.Errorf("expected MaxGas=10000000, got %d", gc.MaxGas)
	}
}

func TestNewRuntime(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	if r == nil {
		t.Fatal("runtime is nil")
	}
	if r.runtimeType != WasmerRuntime {
		t.Errorf("expected WasmerRuntime, got %v", r.runtimeType)
	}
	if r.gasConfig == nil {
		t.Error("gas config should not be nil (default)")
	}
}

func TestNewRuntime_CustomGas(t *testing.T) {
	t.Parallel()
	gc := &GasConfig{CallGas: 500, MaxGas: 5000}
	r := NewRuntime(WasmtimeRuntime, gc)
	if r.gasConfig.CallGas != 500 {
		t.Errorf("expected custom call gas 500, got %d", r.gasConfig.CallGas)
	}
}

func TestRuntime_SetStateStore(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	store := &mockStateStore{}
	r.SetStateStore(store)
	if r.stateStore == nil {
		t.Error("state store should be set")
	}
}

func TestRuntime_RegisterHostFunction(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	r.RegisterHostFunction("test.fn", func(ctx *ExecutionContext, args []Value) ([]Value, error) {
		return nil, nil
	})
	if _, ok := r.hostFunctions["test.fn"]; !ok {
		t.Error("host function not registered")
	}
}

func TestRuntime_LoadModule_Valid(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	// WASM magic number: \0asm
	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, err := r.LoadModule(bytecode)
	if err != nil {
		t.Fatalf("LoadModule() error: %v", err)
	}
	if module == nil {
		t.Fatal("module is nil")
	}
	if module.Hash == [32]byte{} {
		t.Error("module hash should not be zero")
	}
}

func TestRuntime_LoadModule_TooShort(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	_, err := r.LoadModule([]byte{0x00, 0x61})
	if err == nil {
		t.Error("expected error for short bytecode")
	}
}

func TestRuntime_LoadModule_InvalidMagic(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	_, err := r.LoadModule([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0x01, 0x00, 0x00, 0x00})
	if err == nil {
		t.Error("expected error for invalid magic number")
	}
}

func TestRuntime_LoadModule_Dedup(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	m1, _ := r.LoadModule(bytecode)
	m2, _ := r.LoadModule(bytecode)
	if m1.Hash != m2.Hash {
		t.Error("same bytecode should return same module")
	}
}

func TestRuntime_Execute(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, _ := r.LoadModule(bytecode)

	result, err := r.Execute(
		context.Background(),
		module.Hash,
		"main",
		nil,
		100000,
		5*time.Second,
	)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
	if result.GasUsed == 0 {
		t.Error("expected gas consumption")
	}
	if result.Duration <= 0 {
		t.Error("expected positive duration")
	}
}

func TestRuntime_Execute_ModuleNotFound(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	_, err := r.Execute(context.Background(), [32]byte{1}, "main", nil, 100000, time.Second)
	if err == nil {
		t.Error("expected module not found error")
	}
}

func TestRuntime_Execute_OutOfGas(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, _ := r.LoadModule(bytecode)

	// Gas limit too low for CallGas (1000) + execution (1000)
	_, err := r.Execute(context.Background(), module.Hash, "main", nil, 500, time.Second)
	if err == nil {
		t.Error("expected out of gas error")
	}
}

func TestRuntime_Execute_ContextCancelled(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, _ := r.LoadModule(bytecode)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := r.Execute(ctx, module.Hash, "main", nil, 100000, time.Second)
	if err == nil {
		t.Error("expected context cancelled error")
	}
}

func TestRuntime_UnloadModule(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, _ := r.LoadModule(bytecode)

	r.UnloadModule(module.Hash)
	modules := r.GetLoadedModules()
	if len(modules) != 0 {
		t.Errorf("expected 0 modules after unload, got %d", len(modules))
	}
}

func TestRuntime_GetLoadedModules(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	bytecode1 := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	bytecode2 := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x01}
	_, _ = r.LoadModule(bytecode1)
	_, _ = r.LoadModule(bytecode2)

	modules := r.GetLoadedModules()
	if len(modules) != 2 {
		t.Errorf("expected 2 modules, got %d", len(modules))
	}
}

func TestExecutionContext_ConsumeGas(t *testing.T) {
	t.Parallel()
	ctx := &ExecutionContext{gasRemaining: 1000}
	if !ctx.consumeGas(500) {
		t.Error("expected success consuming 500")
	}
	if ctx.gasRemaining != 500 {
		t.Errorf("expected 500 remaining, got %d", ctx.gasRemaining)
	}
	if ctx.consumeGas(501) {
		t.Error("expected failure consuming 501 from 500")
	}
}

func TestExecutionContext_Log(t *testing.T) {
	t.Parallel()
	ctx := &ExecutionContext{logs: make([]string, 0)}
	ctx.Log("test message")
	if len(ctx.logs) != 1 {
		t.Errorf("expected 1 log, got %d", len(ctx.logs))
	}
	if ctx.logs[0] != "test message" {
		t.Errorf("expected 'test message', got %q", ctx.logs[0])
	}
}

func TestExecutionContext_SetState(t *testing.T) {
	t.Parallel()
	ctx := &ExecutionContext{stateChanges: make([]StateChange, 0)}
	err := ctx.SetState([]byte("key"), []byte("val"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ctx.stateChanges) != 1 {
		t.Errorf("expected 1 state change, got %d", len(ctx.stateChanges))
	}
}

func TestExecutionContext_GetState_NoStore(t *testing.T) {
	t.Parallel()
	ctx := &ExecutionContext{}
	_, err := ctx.GetState([]byte("key"))
	if err == nil {
		t.Error("expected error with no state store")
	}
}

func TestExecutionContext_GetState_WithStore(t *testing.T) {
	t.Parallel()
	store := &mockStateStore{data: map[string][]byte{"key": []byte("val")}}
	ctx := &ExecutionContext{stateStore: store}
	val, err := ctx.GetState([]byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	if string(val) != "val" {
		t.Errorf("expected 'val', got %q", val)
	}
}

func TestExecutionContext_GrowMemory(t *testing.T) {
	t.Parallel()
	ctx := &ExecutionContext{
		memory:      make([]byte, 65536),
		memoryPages: 1,
		memoryMax:   5,
	}
	if !ctx.GrowMemory(2) {
		t.Error("expected successful grow")
	}
	if ctx.memoryPages != 3 {
		t.Errorf("expected 3 pages, got %d", ctx.memoryPages)
	}
	if len(ctx.memory) != 3*65536 {
		t.Errorf("expected %d bytes, got %d", 3*65536, len(ctx.memory))
	}

	// Exceed max
	if ctx.GrowMemory(3) {
		t.Error("expected grow failure exceeding max")
	}
}

func TestExecutionContext_ReadWriteMemory(t *testing.T) {
	t.Parallel()
	ctx := &ExecutionContext{
		memory:      make([]byte, 65536),
		memoryPages: 1,
	}

	data := []byte("hello world")
	err := ctx.WriteMemory(100, data)
	if err != nil {
		t.Fatalf("WriteMemory() error: %v", err)
	}

	read, err := ctx.ReadMemory(100, uint32(len(data)))
	if err != nil {
		t.Fatalf("ReadMemory() error: %v", err)
	}
	if string(read) != "hello world" {
		t.Errorf("expected 'hello world', got %q", read)
	}
}

func TestExecutionContext_ReadMemory_OutOfBounds(t *testing.T) {
	t.Parallel()
	ctx := &ExecutionContext{
		memory:      make([]byte, 100),
		memoryPages: 1,
	}
	_, err := ctx.ReadMemory(90, 20) // 90+20 > 100
	if err == nil {
		t.Error("expected out of bounds error")
	}
}

func TestExecutionContext_WriteMemory_OutOfBounds(t *testing.T) {
	t.Parallel()
	ctx := &ExecutionContext{
		memory:      make([]byte, 100),
		memoryPages: 1,
	}
	err := ctx.WriteMemory(90, make([]byte, 20)) // 90+20 > 100
	if err == nil {
		t.Error("expected out of bounds error")
	}
}

func TestStandardHostFunctions(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	expected := []string{"env.log", "env.state_get", "env.state_set", "env.sha256", "env.gas_remaining"}
	for _, name := range expected {
		if _, ok := fns[name]; !ok {
			t.Errorf("expected host function %q", name)
		}
	}
}

func TestValueType_Constants(t *testing.T) {
	t.Parallel()
	if I32 != 0 {
		t.Error("I32 mismatch")
	}
	if I64 != 1 {
		t.Error("I64 mismatch")
	}
	if F32 != 2 {
		t.Error("F32 mismatch")
	}
	if F64 != 3 {
		t.Error("F64 mismatch")
	}
}

func TestRuntimeType_Constants(t *testing.T) {
	t.Parallel()
	if WasmerRuntime != "wasmer" {
		t.Error("WasmerRuntime mismatch")
	}
	if WasmtimeRuntime != "wasmtime" {
		t.Error("WasmtimeRuntime mismatch")
	}
}

func TestStandardHostFunction_EnvLog(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	logFn := fns["env.log"]

	ctx := &ExecutionContext{
		memory: make([]byte, 65536),
		logs:   make([]string, 0),
	}
	copy(ctx.memory[10:], []byte("hello"))

	// Test successful log
	_, err := logFn(ctx, []Value{
		{Type: I32, Data: int32(10)},
		{Type: I32, Data: int32(5)},
	})
	if err != nil {
		t.Fatalf("env.log error: %v", err)
	}
	if len(ctx.logs) != 1 || ctx.logs[0] != "hello" {
		t.Errorf("expected log 'hello', got %v", ctx.logs)
	}

	// Test insufficient args
	_, err = logFn(ctx, []Value{{Type: I32, Data: int32(0)}})
	if err == nil {
		t.Error("expected error for insufficient args")
	}
}

func TestStandardHostFunction_EnvSha256(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	sha256Fn := fns["env.sha256"]

	ctx := &ExecutionContext{
		memory: make([]byte, 65536),
	}
	copy(ctx.memory[0:], []byte("test"))

	_, err := sha256Fn(ctx, []Value{
		{Type: I32, Data: int32(0)},   // inputPtr
		{Type: I32, Data: int32(4)},   // inputLen
		{Type: I32, Data: int32(100)}, // outputPtr
	})
	if err != nil {
		t.Fatalf("env.sha256 error: %v", err)
	}
	// Check that output was written
	output, _ := ctx.ReadMemory(100, 32)
	allZero := true
	for _, b := range output {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("sha256 output should not be all zeros")
	}

	// Test insufficient args
	_, err = sha256Fn(ctx, []Value{{Type: I32, Data: int32(0)}, {Type: I32, Data: int32(4)}})
	if err == nil {
		t.Error("expected error for insufficient args")
	}
}

func TestStandardHostFunction_EnvGasRemaining(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	gasFn := fns["env.gas_remaining"]

	ctx := &ExecutionContext{gasRemaining: 5000}
	result, err := gasFn(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 result, got %d", len(result))
	}
	if result[0].Data.(int64) != 5000 {
		t.Errorf("expected 5000, got %v", result[0].Data)
	}
}

func TestStandardHostFunction_EnvStateGet(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	stateGetFn := fns["env.state_get"]

	store := &mockStateStore{data: map[string][]byte{"mykey": []byte("myval")}}
	ctx := &ExecutionContext{
		memory:     make([]byte, 65536),
		stateStore: store,
	}
	// Write "mykey" at offset 0
	copy(ctx.memory[0:], []byte("mykey"))

	result, err := stateGetFn(ctx, []Value{
		{Type: I32, Data: int32(0)},    // keyPtr
		{Type: I32, Data: int32(5)},    // keyLen
		{Type: I32, Data: int32(100)},  // valPtr
		{Type: I32, Data: int32(1000)}, // valLen
	})
	if err != nil {
		t.Fatal(err)
	}
	if result[0].Data.(int32) != 5 { // "myval" is 5 bytes
		t.Errorf("expected 5, got %v", result[0].Data)
	}

	// Test insufficient args
	_, err = stateGetFn(ctx, []Value{{Type: I32, Data: int32(0)}})
	if err == nil {
		t.Error("expected error for insufficient args")
	}

	// Test state get with no store (error path)
	ctx2 := &ExecutionContext{
		memory: make([]byte, 65536),
	}
	copy(ctx2.memory[0:], []byte("mykey"))
	result2, err := stateGetFn(ctx2, []Value{
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(5)},
		{Type: I32, Data: int32(100)},
		{Type: I32, Data: int32(1000)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result2[0].Data.(int32) != -1 {
		t.Errorf("expected -1 for missing store, got %v", result2[0].Data)
	}

	// Test buffer too small
	result3, err := stateGetFn(ctx, []Value{
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(5)},
		{Type: I32, Data: int32(100)},
		{Type: I32, Data: int32(2)}, // buffer too small for "myval" (5 bytes)
	})
	if err != nil {
		t.Fatal(err)
	}
	if result3[0].Data.(int32) != -2 {
		t.Errorf("expected -2 for buffer too small, got %v", result3[0].Data)
	}
}

func TestStandardHostFunction_EnvStateSet(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	stateSetFn := fns["env.state_set"]

	ctx := &ExecutionContext{
		memory:       make([]byte, 65536),
		stateChanges: make([]StateChange, 0),
	}
	copy(ctx.memory[0:], []byte("key"))
	copy(ctx.memory[100:], []byte("value"))

	result, err := stateSetFn(ctx, []Value{
		{Type: I32, Data: int32(0)},   // keyPtr
		{Type: I32, Data: int32(3)},   // keyLen
		{Type: I32, Data: int32(100)}, // valPtr
		{Type: I32, Data: int32(5)},   // valLen
	})
	if err != nil {
		t.Fatal(err)
	}
	if result[0].Data.(int32) != 0 {
		t.Errorf("expected 0, got %v", result[0].Data)
	}
	if len(ctx.stateChanges) != 1 {
		t.Errorf("expected 1 state change, got %d", len(ctx.stateChanges))
	}

	// Test insufficient args
	_, err = stateSetFn(ctx, []Value{{Type: I32, Data: int32(0)}})
	if err == nil {
		t.Error("expected error for insufficient args")
	}
}

func TestRuntime_Execute_WithStateStore(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	store := &mockStateStore{data: make(map[string][]byte)}
	r.SetStateStore(store)

	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, _ := r.LoadModule(bytecode)

	result, err := r.Execute(context.Background(), module.Hash, "main", nil, 100000, 5*time.Second)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.MemoryUsed == 0 {
		t.Error("expected non-zero memory usage")
	}
}

func TestRuntime_Execute_GasJustEnough(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, _ := r.LoadModule(bytecode)

	// CallGas=1000, execution needs 1000 more = 2000 total
	result, err := r.Execute(context.Background(), module.Hash, "main", nil, 2000, 5*time.Second)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result.GasUsed != 2000 {
		t.Errorf("expected 2000 gas used, got %d", result.GasUsed)
	}
}

func TestRuntime_Execute_GasJustUnder(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, _ := r.LoadModule(bytecode)

	// CallGas=1000, then execution needs 1000 more. 1999 should fail.
	_, err := r.Execute(context.Background(), module.Hash, "main", nil, 1999, 5*time.Second)
	if err == nil {
		t.Error("expected out of gas error with 1999 gas")
	}
}

func TestExecutionContext_GrowMemory_ZeroPages(t *testing.T) {
	t.Parallel()
	ctx := &ExecutionContext{
		memory:      make([]byte, 65536),
		memoryPages: 1,
		memoryMax:   5,
	}
	if !ctx.GrowMemory(0) {
		t.Error("growing by 0 pages should succeed")
	}
	if ctx.memoryPages != 1 {
		t.Errorf("expected 1 page, got %d", ctx.memoryPages)
	}
}

func TestExecutionContext_ConsumeGas_ExactAmount(t *testing.T) {
	t.Parallel()
	ctx := &ExecutionContext{gasRemaining: 100}
	if !ctx.consumeGas(100) {
		t.Error("consuming exact remaining should succeed")
	}
	if ctx.gasRemaining != 0 {
		t.Errorf("expected 0 remaining, got %d", ctx.gasRemaining)
	}
	if ctx.consumeGas(1) {
		t.Error("consuming from 0 remaining should fail")
	}
}

func TestValueType_ExtendedConstants(t *testing.T) {
	t.Parallel()
	if V128 != 4 {
		t.Error("V128 mismatch")
	}
	if FuncRef != 5 {
		t.Error("FuncRef mismatch")
	}
	if ExternRef != 6 {
		t.Error("ExternRef mismatch")
	}
}

func TestStandardHostFunction_EnvLog_ReadMemoryError(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	logFn := fns["env.log"]

	ctx := &ExecutionContext{
		memory: make([]byte, 10), // Small memory
		logs:   make([]string, 0),
	}
	// Try to read beyond memory bounds
	_, err := logFn(ctx, []Value{
		{Type: I32, Data: int32(5)},
		{Type: I32, Data: int32(100)}, // 5+100 > 10
	})
	if err == nil {
		t.Error("expected memory out of bounds error")
	}
}

func TestStandardHostFunction_EnvSha256_ReadMemoryError(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	sha256Fn := fns["env.sha256"]

	ctx := &ExecutionContext{
		memory: make([]byte, 10),
	}
	// Read beyond memory bounds
	_, err := sha256Fn(ctx, []Value{
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(100)}, // 0+100 > 10
		{Type: I32, Data: int32(0)},
	})
	if err == nil {
		t.Error("expected read memory error")
	}
}

func TestStandardHostFunction_EnvSha256_WriteMemoryError(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	sha256Fn := fns["env.sha256"]

	ctx := &ExecutionContext{
		memory: make([]byte, 100), // Enough to read but not write at high offset
	}
	copy(ctx.memory[0:], []byte("test"))

	// Output pointer too high - 95+32 > 100
	_, err := sha256Fn(ctx, []Value{
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(4)},
		{Type: I32, Data: int32(95)}, // write 32 bytes at offset 95, exceeds 100
	})
	if err == nil {
		t.Error("expected write memory error")
	}
}

func TestStandardHostFunction_EnvStateGet_ReadKeyError(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	stateGetFn := fns["env.state_get"]

	ctx := &ExecutionContext{
		memory: make([]byte, 10),
	}
	_, err := stateGetFn(ctx, []Value{
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(100)}, // exceeds memory
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(100)},
	})
	if err == nil {
		t.Error("expected read key memory error")
	}
}

func TestStandardHostFunction_EnvStateGet_WriteValError(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	stateGetFn := fns["env.state_get"]

	store := &mockStateStore{data: map[string][]byte{"k": []byte("longvalue")}}
	ctx := &ExecutionContext{
		memory:     make([]byte, 20),
		stateStore: store,
	}
	copy(ctx.memory[0:], []byte("k"))

	// valPtr at offset 18 with len(longvalue)=9 => 18+9 > 20
	_, err := stateGetFn(ctx, []Value{
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(1)},
		{Type: I32, Data: int32(18)}, // write at 18, longvalue is 9 bytes = 27 > 20
		{Type: I32, Data: int32(100)},
	})
	if err == nil {
		t.Error("expected write val memory error")
	}
}

func TestStandardHostFunction_EnvStateSet_ReadKeyError(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	stateSetFn := fns["env.state_set"]

	ctx := &ExecutionContext{
		memory:       make([]byte, 10),
		stateChanges: make([]StateChange, 0),
	}
	_, err := stateSetFn(ctx, []Value{
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(100)}, // exceeds memory
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(5)},
	})
	if err == nil {
		t.Error("expected read key memory error")
	}
}

func TestStandardHostFunction_EnvStateSet_ReadValError(t *testing.T) {
	t.Parallel()
	fns := StandardHostFunctions()
	stateSetFn := fns["env.state_set"]

	ctx := &ExecutionContext{
		memory:       make([]byte, 10),
		stateChanges: make([]StateChange, 0),
	}
	_, err := stateSetFn(ctx, []Value{
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(3)}, // valid key read
		{Type: I32, Data: int32(0)},
		{Type: I32, Data: int32(100)}, // exceeds memory for value
	})
	if err == nil {
		t.Error("expected read val memory error")
	}
}

func TestRuntime_Execute_ZeroTimeout(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, _ := r.LoadModule(bytecode)

	// Zero timeout - the executeFunction will skip timeout check
	result, err := r.Execute(context.Background(), module.Hash, "main", nil, 100000, 0)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

func TestRuntime_Execute_WithArgs(t *testing.T) {
	t.Parallel()
	r := NewRuntime(WasmerRuntime, nil)
	bytecode := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	module, _ := r.LoadModule(bytecode)

	args := []Value{
		{Type: I32, Data: int32(42)},
		{Type: I64, Data: int64(100)},
	}
	result, err := r.Execute(context.Background(), module.Hash, "compute", args, 100000, 5*time.Second)
	if err != nil {
		t.Fatalf("Execute() error: %v", err)
	}
	if len(result.Returns) == 0 {
		t.Error("expected return values")
	}
}

// --- mock state store ---

type mockStateStore struct {
	data map[string][]byte
}

func (m *mockStateStore) Get(key []byte) ([]byte, error) {
	if m.data == nil {
		return nil, errors.New("not found")
	}
	v, ok := m.data[string(key)]
	if !ok {
		return nil, errors.New("not found")
	}
	return v, nil
}

func (m *mockStateStore) Set(key, value []byte) error {
	if m.data == nil {
		m.data = make(map[string][]byte)
	}
	m.data[string(key)] = value
	return nil
}

func (m *mockStateStore) Delete(key []byte) error {
	delete(m.data, string(key))
	return nil
}

func (m *mockStateStore) Has(key []byte) (bool, error) {
	_, ok := m.data[string(key)]
	return ok, nil
}
