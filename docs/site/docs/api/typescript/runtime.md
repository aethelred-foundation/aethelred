# TypeScript SDK -- Runtime API

## Overview

The runtime module manages device selection, memory allocation, and WebGPU acceleration. Import from the core package:

```typescript
import { Runtime, Device, DeviceType, MemoryPool, Stream } from '@aethelred/sdk';
```

---

## `Runtime`

Singleton that manages hardware backends and execution streams.

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `initialize` | `initialize(options?: RuntimeOptions): void` | Detect devices and start memory pools |
| `shutdown` | `shutdown(): void` | Release all resources and GPU contexts |
| `getDevice` | `getDevice(type: DeviceType, index?: number): Device` | Return a device handle |
| `listDevices` | `listDevices(): Device[]` | Enumerate all available devices |
| `getDefaultDevice` | `getDefaultDevice(): Device` | Return the current default device |
| `setDefaultDevice` | `setDefaultDevice(device: Device): void` | Change the default device |

### `RuntimeOptions`

```typescript
interface RuntimeOptions {
  enableProfiling?: boolean;   // default false
  threadPoolSize?: number;     // default 8
  defaultDevice?: DeviceType;  // default 'cpu'
  webgpu?: WebGPUOptions;
}

interface WebGPUOptions {
  powerPreference?: 'low-power' | 'high-performance';
  requiredFeatures?: string[];
  requiredLimits?: Record<string, number>;
}
```

### Example

```typescript
const rt = new Runtime();
rt.initialize({ enableProfiling: true, defaultDevice: 'webgpu' });

const devices = rt.listDevices();
console.log(`Found ${devices.length} device(s)`);

// Use a specific GPU
const gpu = rt.getDevice('webgpu', 0);
```

---

## `Device`

Represents a compute device (CPU, WebGPU, or TEE enclave).

### Properties

| Property | Type | Description |
|----------|------|-------------|
| `type` | `DeviceType` | `'cpu' \| 'webgpu' \| 'tee'` |
| `index` | `number` | Device index within its type |
| `name` | `string` | Human-readable device name |
| `available` | `boolean` | Whether the device is usable |
| `capabilities` | `DeviceCapabilities` | Memory limits, feature flags |

### `DeviceCapabilities`

```typescript
interface DeviceCapabilities {
  maxBufferSize: number;
  maxStorageBufferBindingSize: number;
  maxComputeWorkgroupsPerDimension: number;
  maxComputeWorkgroupSizeX: number;
  supportsF16: boolean;
  supportsBF16: boolean;
}
```

---

## `MemoryPool`

Pre-allocated memory region for efficient tensor allocation.

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `allocate` | `allocate(bytes: number): MemoryBlock` | Reserve a contiguous block |
| `free` | `free(block: MemoryBlock): void` | Return a block to the pool |
| `stats` | `stats(): { used: number; free: number; total: number }` | Current utilization |
| `reset` | `reset(): void` | Free all blocks |

### Example

```typescript
const pool = new MemoryPool({ sizeBytes: 1024 * 1024 * 256 }); // 256 MB
const block = pool.allocate(4 * 1024 * 1024); // 4 MB for a tensor

console.log(pool.stats());
// { used: 4194304, free: 264241152, total: 268435456 }

pool.free(block);
```

---

## `Stream`

Execution stream for ordering asynchronous GPU operations.

### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `enqueue` | `enqueue(op: () => Promise<void>): void` | Add an operation to the stream |
| `synchronize` | `synchronize(): Promise<void>` | Wait for all enqueued ops to finish |
| `recordEvent` | `recordEvent(): Event` | Create a timing marker |

---

## WebGPU Detection

```typescript
import { hasWebGPU, requestWebGPUDevice } from '@aethelred/sdk';

if (await hasWebGPU()) {
  const device = await requestWebGPUDevice({
    powerPreference: 'high-performance',
  });
  console.log(`WebGPU device: ${device.name}`);
} else {
  console.log('Falling back to CPU');
}
```

---

## See Also

- [TypeScript SDK Overview](./) -- Installation and quick start
- [Tensor API](./tensor) -- Tensor creation and operations
- [Go SDK -- Runtime](/api/go/runtime) -- Go runtime equivalent
