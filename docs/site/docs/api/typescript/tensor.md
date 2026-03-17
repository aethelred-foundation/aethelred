# TypeScript SDK -- Tensor API

## Overview

The `Tensor` class provides multi-dimensional array operations with lazy evaluation, automatic broadcasting, and optional WebGPU acceleration. Import from the core package:

```typescript
import { Tensor, DType } from '@aethelred/sdk';
```

---

## `DType`

Supported data types:

| DType | Description | Bytes |
|-------|-------------|-------|
| `'float32'` | 32-bit float (default) | 4 |
| `'float16'` | 16-bit float | 2 |
| `'bfloat16'` | Brain float 16 | 2 |
| `'int32'` | 32-bit integer | 4 |
| `'int8'` | 8-bit integer | 1 |
| `'uint8'` | Unsigned 8-bit integer | 1 |
| `'bool'` | Boolean | 1 |

---

## Creating Tensors

### Factory Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `constructor` | `new Tensor(data, options?)` | From nested arrays or flat array with shape |
| `zeros` | `Tensor.zeros(shape, options?)` | All zeros |
| `ones` | `Tensor.ones(shape, options?)` | All ones |
| `full` | `Tensor.full(shape, value, options?)` | Filled with a scalar |
| `rand` | `Tensor.rand(shape, options?)` | Uniform random in [0, 1) |
| `randn` | `Tensor.randn(shape, options?)` | Standard normal distribution |

### `TensorOptions`

```typescript
interface TensorOptions {
  shape?: number[];
  dtype?: DType;
  device?: string;          // 'cpu' | 'webgpu'
  requiresGrad?: boolean;
}
```

### Examples

```typescript
// From data
const a = new Tensor([1, 2, 3, 4], { shape: [2, 2] });

// Factory methods
const zeros = Tensor.zeros([3, 3]);
const noise = Tensor.randn([128, 64], { dtype: 'float16', device: 'webgpu' });
```

---

## Properties

| Property | Type | Description |
|----------|------|-------------|
| `shape` | `number[]` | Dimensions of the tensor |
| `dtype` | `DType` | Data type |
| `device` | `string` | Device the data lives on |
| `numel` | `number` | Total element count |
| `ndim` | `number` | Number of dimensions |
| `requiresGrad` | `boolean` | Whether gradients are tracked |
| `grad` | `Tensor \| null` | Accumulated gradient |

---

## Arithmetic Operations

All operations return a new `Tensor` and support broadcasting.

| Method | Signature | Description |
|--------|-----------|-------------|
| `add` | `add(other: Tensor \| number): Tensor` | Element-wise addition |
| `sub` | `sub(other: Tensor \| number): Tensor` | Element-wise subtraction |
| `mul` | `mul(other: Tensor \| number): Tensor` | Element-wise multiplication |
| `div` | `div(other: Tensor \| number): Tensor` | Element-wise division |
| `pow` | `pow(exp: number): Tensor` | Raise to a power |
| `neg` | `neg(): Tensor` | Negate all elements |
| `abs` | `abs(): Tensor` | Absolute value |
| `matmul` | `matmul(other: Tensor): Tensor` | Matrix multiplication |

---

## Reduction Operations

| Method | Signature | Description |
|--------|-----------|-------------|
| `sum` | `sum(dim?: number, keepdim?: boolean): Tensor` | Sum along a dimension |
| `mean` | `mean(dim?: number, keepdim?: boolean): Tensor` | Mean along a dimension |
| `max` | `max(dim?: number, keepdim?: boolean): Tensor` | Max along a dimension |
| `min` | `min(dim?: number, keepdim?: boolean): Tensor` | Min along a dimension |
| `var` | `var(dim?, keepdim?, correction?): Tensor` | Variance |

---

## Shape Operations

| Method | Signature | Description |
|--------|-----------|-------------|
| `reshape` | `reshape(shape: number[]): Tensor` | Return a new view with given shape |
| `permute` | `permute(dims: number[]): Tensor` | Reorder dimensions |
| `transpose` | `transpose(dim0: number, dim1: number): Tensor` | Swap two dimensions |
| `t` | `t(): Tensor` | Transpose a 2-D tensor |
| `squeeze` | `squeeze(dim?: number): Tensor` | Remove size-1 dimensions |
| `unsqueeze` | `unsqueeze(dim: number): Tensor` | Insert a size-1 dimension |

---

## Activation Methods

| Method | Description |
|--------|-------------|
| `relu()` | Rectified linear unit |
| `gelu()` | Gaussian error linear unit |
| `silu()` | Sigmoid linear unit (swish) |
| `sigmoid()` | Logistic sigmoid |
| `tanh()` | Hyperbolic tangent |
| `exp()` | Element-wise exponential |
| `log()` | Element-wise natural logarithm |
| `sqrt()` | Element-wise square root |

---

## TypedArray Interop

```typescript
// To TypedArray
const t = Tensor.randn([4, 4]);
const f32: Float32Array = t.toFloat32Array();

// From TypedArray
const data = new Float32Array([1, 2, 3, 4]);
const t2 = new Tensor(data, { shape: [2, 2] });
```

---

## Lazy Evaluation

Tensor operations build a computation graph and defer execution. Call `realize()` to trigger evaluation:

```typescript
const a = Tensor.randn([1024, 1024], { device: 'webgpu' });
const b = Tensor.randn([1024, 1024], { device: 'webgpu' });
const c = a.matmul(b).relu().sum();  // graph built, not yet computed
await c.realize();                    // execute fused kernel
```

---

## See Also

- [TypeScript SDK Overview](./) -- Installation and quick start
- [Runtime API](./runtime) -- Device selection and memory management
- [Module API](./module) -- Neural network layers that consume tensors
- [Go SDK -- Tensor](/api/go/tensor) -- Go tensor equivalent
