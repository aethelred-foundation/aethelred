# Runtime & Devices

The Aethelred runtime manages hardware resources, memory allocation, and operation scheduling across CPUs, GPUs, and TEE enclaves. It provides a unified execution context that all tensor operations and neural network modules run on top of.

## Initialization

### Go

```go
import "github.com/aethelred/sdk-go/runtime"

// Auto-detect available devices
rt, err := runtime.New(runtime.AutoDetect())
if err != nil {
    log.Fatal(err)
}
defer rt.Close()

fmt.Printf("Devices: %v\n", rt.Devices())
// Devices: [cpu:0, cuda:0, cuda:1]
```

### Rust

```rust
use aethelred::runtime::{Runtime, DeviceType};

let rt = Runtime::builder()
    .device(DeviceType::Cuda(0))
    .memory_pool_size(8 * 1024 * 1024 * 1024)  // 8 GB
    .enable_profiling(true)
    .build()?;

println!("Active device: {}", rt.active_device());
```

### TypeScript

```typescript
import { Runtime, DeviceType } from '@aethelred/sdk';

const rt = new Runtime({
  device: DeviceType.Cuda(0),
  memoryPoolSize: 8 * 1024 ** 3,
});

console.log(`Active device: ${rt.activeDevice}`);
```

## Device Management

### Supported Devices

| Device Type | Identifier | Description |
|---|---|---|
| CPU | `cpu:0` | Default; always available |
| NVIDIA GPU | `cuda:N` | Requires CUDA 12.0+ driver |
| AMD GPU | `rocm:N` | Requires ROCm 5.7+ |
| TEE Enclave | `tee:sgx`, `tee:sev`, `tee:nitro` | Trusted execution; see [TEE Attestation](/guide/tee-attestation) |

### Moving Data Between Devices

```go
// Create tensor on CPU
t := tensor.Randn([]int{1024, 1024}, tensor.Float32, rt.Device("cpu:0"))

// Move to GPU
tGPU := t.To(rt.Device("cuda:0"))

// Move to TEE enclave (encrypted transfer)
tTEE := t.To(rt.Device("tee:sgx"))
```

### Multi-GPU Selection

```rust
// Pin operations to a specific GPU
rt.set_device(DeviceType::Cuda(1))?;

// Or use a device scope
rt.with_device(DeviceType::Cuda(0), || {
    let t = Tensor::randn(&[1024, 1024], DType::Float32)?;
    // all operations here run on cuda:0
    Ok(())
})?;
```

## Memory Pools

The runtime uses memory pools to minimize allocation overhead. Pools are configured per device:

```go
rt, err := runtime.New(
    runtime.WithDevice("cuda:0"),
    runtime.WithMemoryPool("cuda:0", runtime.PoolConfig{
        InitialSize: 2 * 1024 * 1024 * 1024,  // 2 GB initial
        MaxSize:     8 * 1024 * 1024 * 1024,   // 8 GB max
        GrowthFactor: 1.5,
    }),
)
```

### Memory Statistics

```go
stats := rt.MemoryStats("cuda:0")
fmt.Printf("Allocated: %d MB\n", stats.Allocated / 1024 / 1024)
fmt.Printf("Reserved:  %d MB\n", stats.Reserved / 1024 / 1024)
fmt.Printf("Peak:      %d MB\n", stats.Peak / 1024 / 1024)
```

## Execution Modes

### Eager Mode (Default)

Operations execute immediately. Good for debugging and interactive exploration.

```go
a := tensor.Randn([]int{100, 100}, tensor.Float32, device)
b := tensor.Randn([]int{100, 100}, tensor.Float32, device)
c := a.MatMul(b)  // executes immediately
```

### Lazy Mode

Operations are recorded into a computation graph and executed only when results are needed. Enables kernel fusion and other optimizations.

```rust
let rt = Runtime::builder()
    .device(DeviceType::Cuda(0))
    .execution_mode(ExecutionMode::Lazy)
    .build()?;

let a = Tensor::randn(&[100, 100], DType::Float32)?;
let b = Tensor::randn(&[100, 100], DType::Float32)?;
let c = a.matmul(&b)?;       // recorded, not executed
let d = c.relu()?;            // recorded, not executed
let result = d.evaluate()?;   // graph optimized and executed
```

## Profiling

The runtime includes a built-in profiler for identifying performance bottlenecks:

```go
rt.StartProfiling()

// ... run operations ...

profile := rt.StopProfiling()
for _, op := range profile.Operations() {
    fmt.Printf("%-20s %8.2f ms  %6d MB\n",
        op.Name, op.DurationMs, op.MemoryMB)
}

// Export Chrome trace format
profile.ExportTrace("/tmp/aethelred-trace.json")
```

Output:

```
matmul               12.50 ms    512 MB
relu                  0.30 ms      0 MB
layernorm             1.20 ms     64 MB
attention             8.40 ms   1024 MB
```

## Automatic Mixed Precision

Enable AMP to automatically use `float16` for compute-bound operations while keeping `float32` for numerically sensitive operations:

```rust
let rt = Runtime::builder()
    .device(DeviceType::Cuda(0))
    .mixed_precision(MixedPrecisionPolicy::Auto)
    .build()?;
```

## Related Pages

- [Tensor Operations](/guide/tensors) -- tensor API built on the runtime
- [Neural Networks](/guide/neural-networks) -- NN modules use runtime devices
- [Distributed Training](/guide/distributed) -- multi-device training
- [Quantization](/guide/quantization) -- reduced-precision execution
