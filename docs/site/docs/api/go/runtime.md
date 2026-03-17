# Runtime API

## Package `runtime`

The `runtime` package provides the high-performance runtime engine including hardware abstraction, lock-free memory pools, async execution streams, and profiling with Chrome Trace export.

```go
import "github.com/aethelred/sdk-go/pkg/runtime"
```

---

### Runtime

#### `Instance() *Runtime`

Returns the global singleton runtime. Thread-safe via `sync.Once`.

#### `(*Runtime) Initialize() error`

Initializes the runtime, detecting CPU and GPU devices. Safe to call multiple times.

```go
rt := runtime.Instance()
if err := rt.Initialize(); err != nil {
    log.Fatal(err)
}
```

#### `(*Runtime) Devices() []*Device`

Returns a copy of all detected devices (CPU, GPU, TEE enclaves).

#### `(*Runtime) DefaultDevice() *Device`

Returns the current default device (initially CPU).

#### `(*Runtime) SetDefaultDevice(device *Device)`

Sets the default device for tensor allocation.

#### `(*Runtime) IsInitialized() bool`

Reports whether `Initialize` has completed.

#### `(*Runtime) EnableProfiling()` / `DisableProfiling()`

Toggles the built-in profiler.

#### `(*Runtime) Profiler() *Profiler`

Returns the profiler instance for direct access.

---

### Device

#### `NewCPUDevice() *Device`

Creates a CPU device with capabilities derived from `runtime.NumCPU()`.

```go
cpu := runtime.NewCPUDevice()
fmt.Println(cpu.Name) // "CPU (8 cores)"
```

| Field           | Type                 | Description                             |
|-----------------|----------------------|-----------------------------------------|
| `ID`            | `int`                | Device index                            |
| `Type`          | `DeviceType`         | `DeviceCPU`, `DeviceGPU`, etc.          |
| `Name`          | `string`             | Human-readable name                     |
| `Capabilities`  | `DeviceCapabilities` | Hardware feature flags and limits       |
| `IsAvailable`   | `bool`               | Whether the device can accept workloads |
| `NativeBackend` | `bool`               | True if native dispatch is available    |

#### `(*Device) Allocate(size uint64) (*MemoryBlock, error)`

Allocates memory on the device through its memory pool.

#### `(*Device) Free(block *MemoryBlock) error`

Returns a memory block to the pool.

#### `(*Device) Synchronize() error`

Waits for all pending operations on this device.

#### DeviceType constants

| Constant            | Description              |
|---------------------|--------------------------|
| `DeviceCPU`         | CPU device               |
| `DeviceGPU`         | NVIDIA GPU (CUDA)        |
| `DeviceROCm`        | AMD GPU                  |
| `DeviceMetal`       | Apple GPU                |
| `DeviceVulkan`      | Cross-platform GPU       |
| `DeviceIntelSGX`    | Intel SGX enclave        |
| `DeviceAMDSEV`      | AMD SEV enclave          |
| `DeviceAWSNitro`    | AWS Nitro enclave        |
| `DeviceARMTrustZone`| ARM TrustZone            |

---

### MemoryPool

#### `NewMemoryPool(maxSize uint64) *MemoryPool`

Creates a lock-free memory pool with 16 size-class buckets (64 B to 2 MB).

```go
pool := runtime.NewMemoryPool(8 * 1024 * 1024 * 1024) // 8 GB
block, err := pool.Allocate(4096)
defer pool.Free(block)
```

#### `(*MemoryPool) Allocate(size uint64) (*MemoryBlock, error)`

Allocates from the smallest fitting bucket. Sizes exceeding 2 MB bypass the pool.

#### `(*MemoryPool) Free(block *MemoryBlock) error`

Returns memory to the appropriate bucket. Returns `ErrDoubleFree` on repeated calls.

#### `(*MemoryPool) Stats() PoolStats`

Returns current allocation statistics.

| Error sentinel            | Condition                              |
|---------------------------|----------------------------------------|
| `ErrPoolExhausted`        | Allocated bytes exceed `maxSize`       |
| `ErrDoubleFree`           | Block freed more than once             |
| `ErrInvalidPointer`       | Block does not belong to this pool     |
| `ErrDeviceUnavailable`    | Device cannot execute workloads        |
| `ErrNativeBackendRequired`| Non-CPU device without native backend  |

---

### Stream

#### `NewStream(device *Device) *Stream`

Creates an async execution stream bound to a device.

```go
stream := runtime.NewStream(cpu)
stream.Enqueue(func() { fmt.Println("op 1") })
stream.ExecuteAsync()
stream.Synchronize()
```

#### `(*Stream) Enqueue(op func())`

Appends an operation to the pending queue.

#### `(*Stream) Execute()` / `ExecuteAsync()`

Runs pending operations synchronously or in a goroutine.

#### `(*Stream) Synchronize()`

Blocks until all async operations complete.

#### `(*Stream) WaitFor(event *Event)`

Adds a dependency; the stream waits for the event before executing.

#### `(*Stream) RecordEvent() *Event`

Inserts a synchronization event at the current queue position.

---

### Profiler

#### `NewProfiler() *Profiler`

Creates a profiler. Enable it with `Enable()` before recording events.

```go
prof := runtime.NewProfiler()
prof.Enable()
scope := prof.Scope("matmul", runtime.ProfileKernelLaunch)
// ... work ...
scope.End()
fmt.Println(prof.ExportChromeTrace())
```

#### `(*Profiler) Scope(name string, eventType ProfileEventType) *ProfileScope`

Returns a scoped timer. Call `End()` to record the event.

#### `(*Profiler) Summary() ProfileSummary`

Returns per-event-name min/max/avg timing and counts.

#### `(*Profiler) ExportChromeTrace() string`

Exports all events as a `chrome://tracing` compatible JSON string.

---

### Related packages

- [tensor](/api/go/tensor) -- Tensor operations backed by this runtime
- [nn](/api/go/nn) -- Neural network modules
- [Go SDK index](/api/go/) -- Top-level SDK entry points
