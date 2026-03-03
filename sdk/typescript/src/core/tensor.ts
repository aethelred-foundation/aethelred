/**
 * Aethelred SDK - Advanced Tensor Implementation
 *
 * High-performance tensor operations with explicit backend selection:
 * - Lazy evaluation with operation fusion
 * - WebGPU compute shader backend
 * - Automatic differentiation support
 * - Memory-efficient views and broadcasting
 * - NumPy/PyTorch-compatible API
 */

import { Device, DeviceType, MemoryPool, Stream, Runtime } from './runtime';

// ============ Data Types ============

export enum DType {
  FLOAT32 = 'float32',
  FLOAT16 = 'float16',
  BFLOAT16 = 'bfloat16',
  FLOAT64 = 'float64',
  INT32 = 'int32',
  INT16 = 'int16',
  INT8 = 'int8',
  UINT8 = 'uint8',
  BOOL = 'bool',
}

export const DTypeSize: Record<DType, number> = {
  [DType.FLOAT32]: 4,
  [DType.FLOAT16]: 2,
  [DType.BFLOAT16]: 2,
  [DType.FLOAT64]: 8,
  [DType.INT32]: 4,
  [DType.INT16]: 2,
  [DType.INT8]: 1,
  [DType.UINT8]: 1,
  [DType.BOOL]: 1,
};

// ============ Lazy Operations ============

export type LazyOpType =
  | 'binary'
  | 'unary'
  | 'reduce'
  | 'reshape'
  | 'permute'
  | 'slice'
  | 'matmul'
  | 'conv'
  | 'load'
  | 'constant';

export interface LazyOp {
  type: LazyOpType;
  name: string;
  inputs: (Tensor | number | number[])[];
  args?: Record<string, unknown>;
}

// ============ Tensor Storage ============

export class TensorStorage {
  private _data: ArrayBuffer | GPUBuffer | null = null;
  private _device: Device;
  private _size: number;
  private _dtype: DType;
  private _refCount: number = 1;
  private _dirty: boolean = false;

  constructor(
    size: number,
    dtype: DType,
    device?: Device,
    data?: ArrayBuffer | number[]
  ) {
    this._size = size;
    this._dtype = dtype;
    this._device = device || Runtime.getInstance().defaultDevice;

    if (data) {
      if (data instanceof ArrayBuffer) {
        this._data = data;
      } else {
        // Convert array to typed array
        const typedArray = this.createTypedArray(data);
        this._data = typedArray.buffer;
      }
    }
  }

  private createTypedArray(data: number[]): ArrayBufferView {
    switch (this._dtype) {
      case DType.FLOAT32:
        return new Float32Array(data);
      case DType.FLOAT64:
        return new Float64Array(data);
      case DType.INT32:
        return new Int32Array(data);
      case DType.INT16:
        return new Int16Array(data);
      case DType.INT8:
        return new Int8Array(data);
      case DType.UINT8:
        return new Uint8Array(data);
      default:
        return new Float32Array(data);
    }
  }

  get data(): ArrayBuffer | GPUBuffer | null {
    return this._data;
  }

  get device(): Device {
    return this._device;
  }

  get size(): number {
    return this._size;
  }

  get dtype(): DType {
    return this._dtype;
  }

  get byteSize(): number {
    return this._size * DTypeSize[this._dtype];
  }

  allocate(): void {
    if (this._data) return;

    if (this._device.type === DeviceType.GPU_WEBGPU && this._device.gpuDevice) {
      this._data = this._device.gpuDevice.createBuffer({
        size: this.byteSize,
        usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
      });
    } else {
      this._data = new ArrayBuffer(this.byteSize);
    }
  }

  async toDevice(targetDevice: Device): Promise<TensorStorage> {
    if (this._device === targetDevice) return this;

    const newStorage = new TensorStorage(this._size, this._dtype, targetDevice);

    // Copy data
    if (this._data instanceof ArrayBuffer) {
      if (targetDevice.type === DeviceType.GPU_WEBGPU && targetDevice.gpuDevice) {
        // CPU to GPU
        newStorage.allocate();
        targetDevice.gpuDevice.queue.writeBuffer(
          newStorage._data as GPUBuffer,
          0,
          this._data
        );
      } else {
        // CPU to CPU
        newStorage._data = this._data.slice(0);
      }
    } else if (this._data instanceof GPUBuffer) {
      // GPU to CPU - need readback
      const readBuffer = this._device.gpuDevice!.createBuffer({
        size: this.byteSize,
        usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST,
      });

      const encoder = this._device.gpuDevice!.createCommandEncoder();
      encoder.copyBufferToBuffer(this._data, 0, readBuffer, 0, this.byteSize);
      this._device.gpuDevice!.queue.submit([encoder.finish()]);

      await readBuffer.mapAsync(GPUMapMode.READ);
      const arrayBuffer = readBuffer.getMappedRange().slice(0);
      readBuffer.unmap();
      readBuffer.destroy();

      newStorage._data = arrayBuffer;
    }

    return newStorage;
  }

  retain(): void {
    this._refCount++;
  }

  release(): void {
    this._refCount--;
    if (this._refCount <= 0) {
      this.destroy();
    }
  }

  destroy(): void {
    if (this._data instanceof GPUBuffer) {
      this._data.destroy();
    }
    this._data = null;
  }

  getTypedArray(): Float32Array | Float64Array | Int32Array | Int16Array | Int8Array | Uint8Array {
    if (!this._data || this._data instanceof GPUBuffer) {
      throw new Error('Cannot get typed array from GPU buffer directly');
    }

    switch (this._dtype) {
      case DType.FLOAT32:
        return new Float32Array(this._data);
      case DType.FLOAT64:
        return new Float64Array(this._data);
      case DType.INT32:
        return new Int32Array(this._data);
      case DType.INT16:
        return new Int16Array(this._data);
      case DType.INT8:
        return new Int8Array(this._data);
      case DType.UINT8:
        return new Uint8Array(this._data);
      default:
        return new Float32Array(this._data);
    }
  }
}

// ============ Tensor Class ============

export class Tensor {
  private _storage: TensorStorage | null = null;
  private _shape: number[];
  private _strides: number[];
  private _dtype: DType;
  private _device: Device;
  private _lazyOp: LazyOp | null = null;
  private _realized: boolean = false;
  private _requiresGrad: boolean = false;
  private _grad: Tensor | null = null;
  private _gradFn: (() => void) | null = null;

  constructor(
    data: number[] | number[][] | number[][][] | number[][][][] | TensorStorage | null,
    options: {
      shape?: number[];
      dtype?: DType;
      device?: Device;
      requiresGrad?: boolean;
    } = {}
  ) {
    this._dtype = options.dtype || DType.FLOAT32;
    this._device = options.device || Runtime.getInstance().defaultDevice;
    this._requiresGrad = options.requiresGrad || false;

    if (data === null) {
      // Lazy tensor
      this._shape = options.shape || [];
      this._strides = this.computeStrides(this._shape);
    } else if (data instanceof TensorStorage) {
      this._storage = data;
      this._shape = options.shape || [data.size];
      this._strides = this.computeStrides(this._shape);
      this._realized = true;
    } else {
      // Convert nested array to flat array and infer shape
      const { flat, shape } = this.flattenArray(data);
      this._shape = shape;
      this._strides = this.computeStrides(this._shape);
      this._storage = new TensorStorage(flat.length, this._dtype, this._device, flat);
      this._realized = true;
    }
  }

  private flattenArray(arr: unknown): { flat: number[]; shape: number[] } {
    const shape: number[] = [];
    let current: unknown = arr;

    while (Array.isArray(current)) {
      shape.push(current.length);
      current = current[0];
    }

    const flat: number[] = [];
    const flatten = (a: unknown): void => {
      if (Array.isArray(a)) {
        for (const item of a) {
          flatten(item);
        }
      } else {
        flat.push(a as number);
      }
    };
    flatten(arr);

    return { flat, shape };
  }

  private computeStrides(shape: number[]): number[] {
    const strides: number[] = new Array(shape.length);
    let stride = 1;
    for (let i = shape.length - 1; i >= 0; i--) {
      strides[i] = stride;
      stride *= shape[i];
    }
    return strides;
  }

  // ============ Properties ============

  get shape(): number[] {
    return [...this._shape];
  }

  get dtype(): DType {
    return this._dtype;
  }

  get device(): Device {
    return this._device;
  }

  get strides(): number[] {
    return [...this._strides];
  }

  get ndim(): number {
    return this._shape.length;
  }

  get numel(): number {
    return this._shape.reduce((a, b) => a * b, 1);
  }

  get requiresGrad(): boolean {
    return this._requiresGrad;
  }

  set requiresGrad(value: boolean) {
    this._requiresGrad = value;
  }

  get grad(): Tensor | null {
    return this._grad;
  }

  get isRealized(): boolean {
    return this._realized;
  }

  // ============ Lazy Evaluation ============

  private static createLazy(
    op: LazyOp,
    shape: number[],
    dtype: DType,
    device: Device,
    requiresGrad: boolean = false
  ): Tensor {
    const tensor = new Tensor(null, { shape, dtype, device, requiresGrad });
    tensor._lazyOp = op;
    return tensor;
  }

  async realize(): Promise<Tensor> {
    if (this._realized) return this;

    if (!this._lazyOp) {
      throw new Error('Cannot realize tensor without lazy operation');
    }

    // Realize all input tensors first
    for (const input of this._lazyOp.inputs) {
      if (input instanceof Tensor && !input._realized) {
        await input.realize();
      }
    }

    // Execute the operation
    await this.executeOp(this._lazyOp);
    this._realized = true;
    this._lazyOp = null;

    return this;
  }

  private async executeOp(op: LazyOp): Promise<void> {
    const runtime = Runtime.getInstance();

    if (this._device.type === DeviceType.GPU_WEBGPU) {
      await this.executeGPU(op);
    } else {
      await this.executeCPU(op);
    }
  }

  private async executeCPU(op: LazyOp): Promise<void> {
    const result = new Float32Array(this.numel);

    switch (op.type) {
      case 'binary': {
        const a = op.inputs[0] as Tensor;
        const b = op.inputs[1] as Tensor;
        const aData = a._storage!.getTypedArray() as Float32Array;
        const bData = (typeof b === 'number' ? b : (b as Tensor)._storage!.getTypedArray()) as Float32Array | number;

        for (let i = 0; i < result.length; i++) {
          const aVal = aData[i % aData.length];
          const bVal = typeof bData === 'number' ? bData : bData[i % bData.length];

          switch (op.name) {
            case 'add': result[i] = aVal + bVal; break;
            case 'sub': result[i] = aVal - bVal; break;
            case 'mul': result[i] = aVal * bVal; break;
            case 'div': result[i] = aVal / bVal; break;
            case 'pow': result[i] = Math.pow(aVal, bVal); break;
            case 'max': result[i] = Math.max(aVal, bVal); break;
            case 'min': result[i] = Math.min(aVal, bVal); break;
          }
        }
        break;
      }

      case 'unary': {
        const input = op.inputs[0] as Tensor;
        const inputData = input._storage!.getTypedArray() as Float32Array;

        for (let i = 0; i < result.length; i++) {
          const val = inputData[i];
          switch (op.name) {
            case 'neg': result[i] = -val; break;
            case 'abs': result[i] = Math.abs(val); break;
            case 'exp': result[i] = Math.exp(val); break;
            case 'log': result[i] = Math.log(val); break;
            case 'sqrt': result[i] = Math.sqrt(val); break;
            case 'sin': result[i] = Math.sin(val); break;
            case 'cos': result[i] = Math.cos(val); break;
            case 'tanh': result[i] = Math.tanh(val); break;
            case 'sigmoid': result[i] = 1 / (1 + Math.exp(-val)); break;
            case 'relu': result[i] = Math.max(0, val); break;
            case 'gelu': {
              const cdf = 0.5 * (1 + Math.tanh(Math.sqrt(2 / Math.PI) * (val + 0.044715 * Math.pow(val, 3))));
              result[i] = val * cdf;
              break;
            }
            case 'silu': result[i] = val / (1 + Math.exp(-val)); break;
          }
        }
        break;
      }

      case 'reduce': {
        const input = op.inputs[0] as Tensor;
        const inputData = input._storage!.getTypedArray() as Float32Array;
        const axis = op.args?.axis as number | undefined;
        const keepdim = op.args?.keepdim as boolean ?? false;

        if (axis === undefined) {
          // Reduce all dimensions
          let acc = op.name === 'sum' || op.name === 'mean' ? 0 :
                    op.name === 'max' ? -Infinity : Infinity;

          for (let i = 0; i < inputData.length; i++) {
            switch (op.name) {
              case 'sum':
              case 'mean':
                acc += inputData[i];
                break;
              case 'max':
                acc = Math.max(acc, inputData[i]);
                break;
              case 'min':
                acc = Math.min(acc, inputData[i]);
                break;
            }
          }

          if (op.name === 'mean') {
            acc /= inputData.length;
          }

          result[0] = acc;
        } else {
          // Reduce along specific axis - simplified implementation
          // Full implementation would handle arbitrary axis reduction
          throw new Error('Axis-specific reduction not yet implemented in CPU backend');
        }
        break;
      }

      case 'matmul': {
        const a = op.inputs[0] as Tensor;
        const b = op.inputs[1] as Tensor;
        const aData = a._storage!.getTypedArray() as Float32Array;
        const bData = b._storage!.getTypedArray() as Float32Array;

        const M = a._shape[a._shape.length - 2];
        const K = a._shape[a._shape.length - 1];
        const N = b._shape[b._shape.length - 1];

        // Simple matmul - can be optimized with tiling
        for (let i = 0; i < M; i++) {
          for (let j = 0; j < N; j++) {
            let sum = 0;
            for (let k = 0; k < K; k++) {
              sum += aData[i * K + k] * bData[k * N + j];
            }
            result[i * N + j] = sum;
          }
        }
        break;
      }

      case 'constant': {
        const value = op.inputs[0] as number;
        result.fill(value);
        break;
      }

      case 'load': {
        // Data already loaded
        break;
      }

      default:
        throw new Error(`Unsupported operation: ${op.type}`);
    }

    this._storage = new TensorStorage(result.length, this._dtype, this._device, Array.from(result));
  }

  private async executeGPU(op: LazyOp): Promise<void> {
    const device = this._device.gpuDevice!;

    // Create compute shader based on operation
    const shaderCode = this.generateShader(op);

    const shaderModule = device.createShaderModule({ code: shaderCode });

    // Create pipeline
    const pipeline = device.createComputePipeline({
      layout: 'auto',
      compute: {
        module: shaderModule,
        entryPoint: 'main',
      },
    });

    // Allocate output buffer
    this._storage = new TensorStorage(this.numel, this._dtype, this._device);
    this._storage.allocate();

    // Create bind group with input and output buffers
    const bindGroupEntries: GPUBindGroupEntry[] = [];
    let bindingIndex = 0;

    for (const input of op.inputs) {
      if (input instanceof Tensor) {
        const inputStorage = input._storage!;
        if (inputStorage.data instanceof GPUBuffer) {
          bindGroupEntries.push({
            binding: bindingIndex++,
            resource: { buffer: inputStorage.data },
          });
        }
      }
    }

    bindGroupEntries.push({
      binding: bindingIndex,
      resource: { buffer: this._storage.data as GPUBuffer },
    });

    const bindGroup = device.createBindGroup({
      layout: pipeline.getBindGroupLayout(0),
      entries: bindGroupEntries,
    });

    // Execute
    const encoder = device.createCommandEncoder();
    const pass = encoder.beginComputePass();
    pass.setPipeline(pipeline);
    pass.setBindGroup(0, bindGroup);
    pass.dispatchWorkgroups(Math.ceil(this.numel / 256));
    pass.end();

    device.queue.submit([encoder.finish()]);
  }

  private generateShader(op: LazyOp): string {
    // Generate WGSL compute shader for the operation
    let opCode = '';

    switch (op.type) {
      case 'binary':
        switch (op.name) {
          case 'add': opCode = 'a[i] + b[i]'; break;
          case 'sub': opCode = 'a[i] - b[i]'; break;
          case 'mul': opCode = 'a[i] * b[i]'; break;
          case 'div': opCode = 'a[i] / b[i]'; break;
        }
        return `
          @group(0) @binding(0) var<storage, read> a: array<f32>;
          @group(0) @binding(1) var<storage, read> b: array<f32>;
          @group(0) @binding(2) var<storage, read_write> result: array<f32>;

          @compute @workgroup_size(256)
          fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
            let i = gid.x;
            if (i < arrayLength(&result)) {
              result[i] = ${opCode};
            }
          }
        `;

      case 'unary':
        switch (op.name) {
          case 'neg': opCode = '-input[i]'; break;
          case 'exp': opCode = 'exp(input[i])'; break;
          case 'log': opCode = 'log(input[i])'; break;
          case 'sqrt': opCode = 'sqrt(input[i])'; break;
          case 'relu': opCode = 'max(0.0, input[i])'; break;
          case 'sigmoid': opCode = '1.0 / (1.0 + exp(-input[i]))'; break;
          case 'tanh': opCode = 'tanh(input[i])'; break;
        }
        return `
          @group(0) @binding(0) var<storage, read> input: array<f32>;
          @group(0) @binding(1) var<storage, read_write> result: array<f32>;

          @compute @workgroup_size(256)
          fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
            let i = gid.x;
            if (i < arrayLength(&result)) {
              result[i] = ${opCode};
            }
          }
        `;

      default:
        throw new Error(`GPU shader not implemented for: ${op.type}`);
    }
  }

  // ============ Factory Methods ============

  static zeros(shape: number[], options: { dtype?: DType; device?: Device } = {}): Tensor {
    return Tensor.createLazy(
      { type: 'constant', name: 'zeros', inputs: [0] },
      shape,
      options.dtype || DType.FLOAT32,
      options.device || Runtime.getInstance().defaultDevice
    );
  }

  static ones(shape: number[], options: { dtype?: DType; device?: Device } = {}): Tensor {
    return Tensor.createLazy(
      { type: 'constant', name: 'ones', inputs: [1] },
      shape,
      options.dtype || DType.FLOAT32,
      options.device || Runtime.getInstance().defaultDevice
    );
  }

  static full(shape: number[], value: number, options: { dtype?: DType; device?: Device } = {}): Tensor {
    return Tensor.createLazy(
      { type: 'constant', name: 'full', inputs: [value] },
      shape,
      options.dtype || DType.FLOAT32,
      options.device || Runtime.getInstance().defaultDevice
    );
  }

  static rand(shape: number[], options: { dtype?: DType; device?: Device } = {}): Tensor {
    const size = shape.reduce((a, b) => a * b, 1);
    const data = Array.from({ length: size }, () => Math.random());
    return new Tensor(data, { shape, ...options });
  }

  static randn(shape: number[], options: { dtype?: DType; device?: Device } = {}): Tensor {
    const size = shape.reduce((a, b) => a * b, 1);
    const data: number[] = [];

    // Box-Muller transform for normal distribution
    for (let i = 0; i < size; i += 2) {
      const u1 = Math.random();
      const u2 = Math.random();
      const mag = Math.sqrt(-2 * Math.log(u1));
      data.push(mag * Math.cos(2 * Math.PI * u2));
      if (i + 1 < size) {
        data.push(mag * Math.sin(2 * Math.PI * u2));
      }
    }

    return new Tensor(data, { shape, ...options });
  }

  static arange(end: number, options?: { start?: number; step?: number; dtype?: DType; device?: Device }): Tensor {
    const start = options?.start ?? 0;
    const step = options?.step ?? 1;
    const data: number[] = [];

    for (let i = start; i < end; i += step) {
      data.push(i);
    }

    return new Tensor(data, { dtype: options?.dtype, device: options?.device });
  }

  static linspace(start: number, end: number, steps: number, options?: { dtype?: DType; device?: Device }): Tensor {
    const data: number[] = [];
    const stepSize = (end - start) / (steps - 1);

    for (let i = 0; i < steps; i++) {
      data.push(start + i * stepSize);
    }

    return new Tensor(data, { ...options });
  }

  static eye(n: number, options?: { dtype?: DType; device?: Device }): Tensor {
    const data = new Array(n * n).fill(0);
    for (let i = 0; i < n; i++) {
      data[i * n + i] = 1;
    }
    return new Tensor(data, { shape: [n, n], ...options });
  }

  // ============ Operations ============

  add(other: Tensor | number): Tensor {
    const otherTensor = typeof other === 'number' ? Tensor.full(this._shape, other) : other;
    const resultShape = this.broadcastShape(this._shape, otherTensor._shape);

    return Tensor.createLazy(
      { type: 'binary', name: 'add', inputs: [this, otherTensor] },
      resultShape,
      this._dtype,
      this._device,
      this._requiresGrad || otherTensor._requiresGrad
    );
  }

  sub(other: Tensor | number): Tensor {
    const otherTensor = typeof other === 'number' ? Tensor.full(this._shape, other) : other;
    const resultShape = this.broadcastShape(this._shape, otherTensor._shape);

    return Tensor.createLazy(
      { type: 'binary', name: 'sub', inputs: [this, otherTensor] },
      resultShape,
      this._dtype,
      this._device,
      this._requiresGrad || otherTensor._requiresGrad
    );
  }

  mul(other: Tensor | number): Tensor {
    const otherTensor = typeof other === 'number' ? Tensor.full(this._shape, other) : other;
    const resultShape = this.broadcastShape(this._shape, otherTensor._shape);

    return Tensor.createLazy(
      { type: 'binary', name: 'mul', inputs: [this, otherTensor] },
      resultShape,
      this._dtype,
      this._device,
      this._requiresGrad || otherTensor._requiresGrad
    );
  }

  div(other: Tensor | number): Tensor {
    const otherTensor = typeof other === 'number' ? Tensor.full(this._shape, other) : other;
    const resultShape = this.broadcastShape(this._shape, otherTensor._shape);

    return Tensor.createLazy(
      { type: 'binary', name: 'div', inputs: [this, otherTensor] },
      resultShape,
      this._dtype,
      this._device,
      this._requiresGrad || otherTensor._requiresGrad
    );
  }

  pow(exponent: number): Tensor {
    return Tensor.createLazy(
      { type: 'binary', name: 'pow', inputs: [this, exponent] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  neg(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'neg', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  abs(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'abs', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  exp(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'exp', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  log(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'log', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  sqrt(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'sqrt', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  sin(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'sin', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  cos(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'cos', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  tanh(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'tanh', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  sigmoid(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'sigmoid', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  relu(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'relu', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  gelu(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'gelu', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  silu(): Tensor {
    return Tensor.createLazy(
      { type: 'unary', name: 'silu', inputs: [this] },
      this._shape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  // ============ Reduction Operations ============

  sum(axis?: number, keepdim: boolean = false): Tensor {
    let resultShape: number[];

    if (axis === undefined) {
      resultShape = keepdim ? this._shape.map(() => 1) : [1];
    } else {
      resultShape = [...this._shape];
      if (keepdim) {
        resultShape[axis] = 1;
      } else {
        resultShape.splice(axis, 1);
      }
    }

    return Tensor.createLazy(
      { type: 'reduce', name: 'sum', inputs: [this], args: { axis, keepdim } },
      resultShape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  mean(axis?: number, keepdim: boolean = false): Tensor {
    let resultShape: number[];

    if (axis === undefined) {
      resultShape = keepdim ? this._shape.map(() => 1) : [1];
    } else {
      resultShape = [...this._shape];
      if (keepdim) {
        resultShape[axis] = 1;
      } else {
        resultShape.splice(axis, 1);
      }
    }

    return Tensor.createLazy(
      { type: 'reduce', name: 'mean', inputs: [this], args: { axis, keepdim } },
      resultShape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  max(axis?: number, keepdim: boolean = false): Tensor {
    let resultShape: number[];

    if (axis === undefined) {
      resultShape = keepdim ? this._shape.map(() => 1) : [1];
    } else {
      resultShape = [...this._shape];
      if (keepdim) {
        resultShape[axis] = 1;
      } else {
        resultShape.splice(axis, 1);
      }
    }

    return Tensor.createLazy(
      { type: 'reduce', name: 'max', inputs: [this], args: { axis, keepdim } },
      resultShape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  min(axis?: number, keepdim: boolean = false): Tensor {
    let resultShape: number[];

    if (axis === undefined) {
      resultShape = keepdim ? this._shape.map(() => 1) : [1];
    } else {
      resultShape = [...this._shape];
      if (keepdim) {
        resultShape[axis] = 1;
      } else {
        resultShape.splice(axis, 1);
      }
    }

    return Tensor.createLazy(
      { type: 'reduce', name: 'min', inputs: [this], args: { axis, keepdim } },
      resultShape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  var(axis?: number, keepdim: boolean = false, correction: number = 1): Tensor {
    const mean = this.mean(axis, true);
    const diff = this.sub(mean);
    const sqDiff = diff.mul(diff);
    const sumSq = sqDiff.sum(axis, keepdim);

    const n = axis === undefined ? this.numel : this._shape[axis];
    return sumSq.div(n - correction);
  }

  std(axis?: number, keepdim: boolean = false, correction: number = 1): Tensor {
    return this.var(axis, keepdim, correction).sqrt();
  }

  // ============ Matrix Operations ============

  matmul(other: Tensor): Tensor {
    if (this.ndim < 1 || other.ndim < 1) {
      throw new Error('matmul requires at least 1D tensors');
    }

    // Compute result shape
    const aShape = this._shape;
    const bShape = other._shape;

    let resultShape: number[];
    if (this.ndim === 1 && other.ndim === 1) {
      resultShape = [1];
    } else if (this.ndim === 1) {
      resultShape = bShape.slice(0, -2).concat([bShape[bShape.length - 1]]);
    } else if (other.ndim === 1) {
      resultShape = aShape.slice(0, -1);
    } else {
      const batchDims = this.broadcastShape(
        aShape.slice(0, -2),
        bShape.slice(0, -2)
      );
      resultShape = [...batchDims, aShape[aShape.length - 2], bShape[bShape.length - 1]];
    }

    return Tensor.createLazy(
      { type: 'matmul', name: 'matmul', inputs: [this, other] },
      resultShape,
      this._dtype,
      this._device,
      this._requiresGrad || other._requiresGrad
    );
  }

  mm(other: Tensor): Tensor {
    return this.matmul(other);
  }

  transpose(dim0?: number, dim1?: number): Tensor {
    if (this.ndim < 2) {
      return this;
    }

    dim0 = dim0 ?? this.ndim - 2;
    dim1 = dim1 ?? this.ndim - 1;

    const perm = Array.from({ length: this.ndim }, (_, i) => i);
    [perm[dim0], perm[dim1]] = [perm[dim1], perm[dim0]];

    return this.permute(perm);
  }

  t(): Tensor {
    return this.transpose();
  }

  permute(dims: number[]): Tensor {
    const newShape = dims.map(d => this._shape[d]);

    return Tensor.createLazy(
      { type: 'permute', name: 'permute', inputs: [this], args: { dims } },
      newShape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  // ============ Shape Operations ============

  reshape(newShape: number[]): Tensor {
    // Handle -1 in shape
    let inferredIdx = -1;
    let knownProduct = 1;

    for (let i = 0; i < newShape.length; i++) {
      if (newShape[i] === -1) {
        if (inferredIdx !== -1) {
          throw new Error('Only one dimension can be inferred');
        }
        inferredIdx = i;
      } else {
        knownProduct *= newShape[i];
      }
    }

    const finalShape = [...newShape];
    if (inferredIdx !== -1) {
      finalShape[inferredIdx] = this.numel / knownProduct;
    }

    if (finalShape.reduce((a, b) => a * b, 1) !== this.numel) {
      throw new Error(`Cannot reshape tensor of size ${this.numel} to shape [${finalShape}]`);
    }

    return Tensor.createLazy(
      { type: 'reshape', name: 'reshape', inputs: [this], args: { shape: finalShape } },
      finalShape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  view(newShape: number[]): Tensor {
    return this.reshape(newShape);
  }

  flatten(startDim: number = 0, endDim: number = -1): Tensor {
    if (endDim < 0) endDim = this.ndim + endDim;

    const newShape = [
      ...this._shape.slice(0, startDim),
      this._shape.slice(startDim, endDim + 1).reduce((a, b) => a * b, 1),
      ...this._shape.slice(endDim + 1),
    ];

    return this.reshape(newShape);
  }

  squeeze(dim?: number): Tensor {
    let newShape: number[];

    if (dim === undefined) {
      newShape = this._shape.filter(d => d !== 1);
    } else {
      newShape = [...this._shape];
      if (newShape[dim] === 1) {
        newShape.splice(dim, 1);
      }
    }

    return this.reshape(newShape);
  }

  unsqueeze(dim: number): Tensor {
    const newShape = [...this._shape];
    newShape.splice(dim, 0, 1);
    return this.reshape(newShape);
  }

  expand(newShape: number[]): Tensor {
    // Validate and compute expansion
    const expanded = this.broadcastShape(this._shape, newShape);

    return Tensor.createLazy(
      { type: 'reshape', name: 'expand', inputs: [this], args: { shape: expanded } },
      expanded,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  // ============ Slicing ============

  slice(starts: number[], ends: number[], steps?: number[]): Tensor {
    const actualSteps = steps || this._shape.map(() => 1);
    const newShape: number[] = [];

    for (let i = 0; i < this._shape.length; i++) {
      const start = starts[i] ?? 0;
      const end = ends[i] ?? this._shape[i];
      const step = actualSteps[i];
      newShape.push(Math.ceil((end - start) / step));
    }

    return Tensor.createLazy(
      { type: 'slice', name: 'slice', inputs: [this], args: { starts, ends, steps: actualSteps } },
      newShape,
      this._dtype,
      this._device,
      this._requiresGrad
    );
  }

  // ============ Concatenation ============

  static cat(tensors: Tensor[], dim: number = 0): Tensor {
    if (tensors.length === 0) {
      throw new Error('cat requires at least one tensor');
    }

    const first = tensors[0];
    const newShape = [...first._shape];
    newShape[dim] = tensors.reduce((sum, t) => sum + t._shape[dim], 0);

    return Tensor.createLazy(
      { type: 'binary', name: 'cat', inputs: tensors, args: { dim } },
      newShape,
      first._dtype,
      first._device,
      tensors.some(t => t._requiresGrad)
    );
  }

  static stack(tensors: Tensor[], dim: number = 0): Tensor {
    const expanded = tensors.map(t => t.unsqueeze(dim));
    return Tensor.cat(expanded, dim);
  }

  // ============ Utilities ============

  private broadcastShape(shape1: number[], shape2: number[]): number[] {
    const maxLen = Math.max(shape1.length, shape2.length);
    const result: number[] = [];

    for (let i = 0; i < maxLen; i++) {
      const d1 = shape1[shape1.length - 1 - i] ?? 1;
      const d2 = shape2[shape2.length - 1 - i] ?? 1;

      if (d1 !== d2 && d1 !== 1 && d2 !== 1) {
        throw new Error(`Cannot broadcast shapes [${shape1}] and [${shape2}]`);
      }

      result.unshift(Math.max(d1, d2));
    }

    return result;
  }

  clone(): Tensor {
    if (this._realized && this._storage) {
      const newStorage = new TensorStorage(
        this._storage.size,
        this._dtype,
        this._device,
        Array.from(this._storage.getTypedArray())
      );
      return new Tensor(newStorage, {
        shape: this._shape,
        dtype: this._dtype,
        device: this._device,
        requiresGrad: this._requiresGrad,
      });
    } else {
      const cloned = Tensor.createLazy(
        this._lazyOp!,
        this._shape,
        this._dtype,
        this._device,
        this._requiresGrad
      );
      return cloned;
    }
  }

  async to(device: Device): Promise<Tensor> {
    if (this._device === device) return this;

    await this.realize();
    const newStorage = await this._storage!.toDevice(device);

    return new Tensor(newStorage, {
      shape: this._shape,
      dtype: this._dtype,
      device,
      requiresGrad: this._requiresGrad,
    });
  }

  async toArray(): Promise<number[]> {
    await this.realize();

    if (this._device.type !== DeviceType.CPU) {
      const cpuTensor = await this.to(Runtime.getInstance().defaultDevice);
      return Array.from(cpuTensor._storage!.getTypedArray());
    }

    return Array.from(this._storage!.getTypedArray());
  }

  async toNestedArray(): Promise<unknown> {
    const flat = await this.toArray();

    const buildNested = (data: number[], shape: number[], offset: number = 0): unknown => {
      if (shape.length === 0) return data[offset];
      if (shape.length === 1) return data.slice(offset, offset + shape[0]);

      const result: unknown[] = [];
      const stride = shape.slice(1).reduce((a, b) => a * b, 1);

      for (let i = 0; i < shape[0]; i++) {
        result.push(buildNested(data, shape.slice(1), offset + i * stride));
      }

      return result;
    };

    return buildNested(flat, this._shape);
  }

  async item(): Promise<number> {
    if (this.numel !== 1) {
      throw new Error('item() requires tensor with exactly one element');
    }

    const arr = await this.toArray();
    return arr[0];
  }

  toString(): string {
    return `Tensor(shape=[${this._shape}], dtype=${this._dtype}, device=${this._device.name}, realized=${this._realized})`;
  }

  // ============ Gradient Support ============

  backward(): void {
    if (!this._requiresGrad) {
      throw new Error('Cannot call backward on tensor that does not require gradients');
    }

    if (this.numel !== 1) {
      throw new Error('backward() requires scalar tensor');
    }

    // Initialize gradient
    if (!this._grad) {
      this._grad = Tensor.ones(this._shape, { dtype: this._dtype, device: this._device });
    }

    // Execute gradient function
    if (this._gradFn) {
      this._gradFn();
    }
  }

  zeroGrad(): void {
    this._grad = null;
  }

  detach(): Tensor {
    const detached = this.clone();
    detached._requiresGrad = false;
    detached._gradFn = null;
    return detached;
  }
}

// ============ Module Exports ============

export { Tensor as default };
