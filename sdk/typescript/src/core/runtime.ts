/**
 * Aethelred Runtime Engine - TypeScript Edition
 *
 * GPU-aware runtime capabilities for the browser and Node.js:
 * - WebGPU and WebGL compute backends
 * - WebAssembly SIMD acceleration
 * - Worker thread parallelism
 * - Memory pool management
 * - Async execution with streams
 * - Comprehensive profiling
 */

// ============================================================================
// Device Types
// ============================================================================

export enum DeviceType {
  CPU = 'cpu',
  GPU_WEBGPU = 'webgpu',
  GPU_WEBGL = 'webgl',
  WASM = 'wasm',
  WORKER = 'worker',
  REMOTE = 'remote',
}

export enum MemoryType {
  HEAP = 'heap',
  ARRAY_BUFFER = 'array_buffer',
  SHARED_ARRAY_BUFFER = 'shared_array_buffer',
  GPU_BUFFER = 'gpu_buffer',
  TEXTURE = 'texture',
}

export interface DeviceCapabilities {
  deviceType: DeviceType;
  deviceId: number;
  name: string;

  // Memory
  maxMemory: number;
  maxBufferSize: number;
  maxStorageBufferBindingSize: number;

  // Compute
  maxComputeWorkgroupsPerDimension: number;
  maxComputeWorkgroupSizeX: number;
  maxComputeWorkgroupSizeY: number;
  maxComputeWorkgroupSizeZ: number;
  maxComputeInvocationsPerWorkgroup: number;

  // Features
  supportsFloat16: boolean;
  supportsFloat64: boolean;
  supportsTimestampQuery: boolean;
  supportsIndirectDispatch: boolean;

  // WebGPU specific
  adapterInfo?: GPUAdapterInfo;
}

// ============================================================================
// Device Class
// ============================================================================

export class Device {
  private static _instances: Map<string, Device> = new Map();
  private static _current: Device | null = null;
  private static _contextStack: Device[] = [];

  readonly deviceType: DeviceType;
  readonly deviceId: number;
  private _capabilities: DeviceCapabilities | null = null;
  private _memoryPool: MemoryPool | null = null;
  private _defaultStream: Stream | null = null;
  private _streamPool: Stream[] = [];
  private _initialized = false;

  // WebGPU handles
  private _gpuDevice: GPUDevice | null = null;
  private _gpuAdapter: GPUAdapter | null = null;

  constructor(deviceType: DeviceType, deviceId: number = 0) {
    this.deviceType = deviceType;
    this.deviceId = deviceId;
  }

  /**
   * Get the current default device.
   */
  static getDefault(): Device {
    if (this._current) {
      return this._current;
    }

    // Auto-detect best available
    return this.cpu();
  }

  /**
   * Get a CPU device.
   */
  static cpu(deviceId: number = 0): Device {
    const key = `cpu:${deviceId}`;
    if (!this._instances.has(key)) {
      this._instances.set(key, new Device(DeviceType.CPU, deviceId));
    }
    return this._instances.get(key)!;
  }

  /**
   * Get a WebGPU device.
   */
  static async webgpu(deviceId: number = 0): Promise<Device> {
    const key = `webgpu:${deviceId}`;
    if (!this._instances.has(key)) {
      const device = new Device(DeviceType.GPU_WEBGPU, deviceId);
      await device.initialize();
      this._instances.set(key, device);
    }
    return this._instances.get(key)!;
  }

  /**
   * Get a WebGL device.
   */
  static webgl(deviceId: number = 0): Device {
    const key = `webgl:${deviceId}`;
    if (!this._instances.has(key)) {
      this._instances.set(key, new Device(DeviceType.GPU_WEBGL, deviceId));
    }
    return this._instances.get(key)!;
  }

  /**
   * Enumerate all available devices.
   */
  static async enumerateDevices(): Promise<Device[]> {
    const devices: Device[] = [];

    // CPU is always available
    devices.push(this.cpu());

    // Check WebGPU
    if (typeof navigator !== 'undefined' && 'gpu' in navigator) {
      try {
        const adapter = await navigator.gpu.requestAdapter();
        if (adapter) {
          devices.push(await this.webgpu());
        }
      } catch (e) {
        // WebGPU not available
      }
    }

    // Check WebGL
    if (typeof document !== 'undefined') {
      try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl2') || canvas.getContext('webgl');
        if (gl) {
          devices.push(this.webgl());
        }
      } catch (e) {
        // WebGL not available
      }
    }

    return devices;
  }

  /**
   * Initialize the device.
   */
  async initialize(): Promise<void> {
    if (this._initialized) return;

    if (this.deviceType === DeviceType.GPU_WEBGPU) {
      await this._initWebGPU();
    }

    this._memoryPool = new MemoryPool(this);
    this._defaultStream = new Stream(this, true);

    // Pre-allocate stream pool
    for (let i = 0; i < 4; i++) {
      this._streamPool.push(new Stream(this));
    }

    this._initialized = true;
  }

  private async _initWebGPU(): Promise<void> {
    if (typeof navigator === 'undefined' || !('gpu' in navigator)) {
      throw new Error('WebGPU is not supported');
    }

    this._gpuAdapter = await navigator.gpu.requestAdapter({
      powerPreference: 'high-performance',
    });

    if (!this._gpuAdapter) {
      throw new Error('Failed to get WebGPU adapter');
    }

    this._gpuDevice = await this._gpuAdapter.requestDevice({
      requiredFeatures: this._gpuAdapter.features.has('timestamp-query')
        ? ['timestamp-query']
        : [],
      requiredLimits: {
        maxStorageBufferBindingSize: this._gpuAdapter.limits.maxStorageBufferBindingSize,
        maxBufferSize: this._gpuAdapter.limits.maxBufferSize,
      },
    });

    // Handle device loss
    this._gpuDevice.lost.then((info) => {
      console.error(`WebGPU device lost: ${info.message}`);
      this._initialized = false;
    });
  }

  get capabilities(): DeviceCapabilities {
    if (!this._capabilities) {
      this._capabilities = this._detectCapabilities();
    }
    return this._capabilities;
  }

  private _detectCapabilities(): DeviceCapabilities {
    if (this.deviceType === DeviceType.GPU_WEBGPU && this._gpuAdapter) {
      const limits = this._gpuAdapter.limits;
      return {
        deviceType: this.deviceType,
        deviceId: this.deviceId,
        name: 'WebGPU Device',
        maxMemory: limits.maxBufferSize,
        maxBufferSize: limits.maxBufferSize,
        maxStorageBufferBindingSize: limits.maxStorageBufferBindingSize,
        maxComputeWorkgroupsPerDimension: limits.maxComputeWorkgroupsPerDimension,
        maxComputeWorkgroupSizeX: limits.maxComputeWorkgroupSizeX,
        maxComputeWorkgroupSizeY: limits.maxComputeWorkgroupSizeY,
        maxComputeWorkgroupSizeZ: limits.maxComputeWorkgroupSizeZ,
        maxComputeInvocationsPerWorkgroup: limits.maxComputeInvocationsPerWorkgroup,
        supportsFloat16: this._gpuAdapter.features.has('shader-f16'),
        supportsFloat64: false,
        supportsTimestampQuery: this._gpuAdapter.features.has('timestamp-query'),
        supportsIndirectDispatch: true,
        adapterInfo: this._gpuAdapter.info,
      };
    }

    // CPU capabilities
    return {
      deviceType: this.deviceType,
      deviceId: this.deviceId,
      name: typeof navigator !== 'undefined' ? navigator.userAgent : 'Node.js',
      maxMemory: typeof process !== 'undefined'
        ? (process.memoryUsage?.().heapTotal || 4 * 1024 * 1024 * 1024)
        : 4 * 1024 * 1024 * 1024,
      maxBufferSize: 2 * 1024 * 1024 * 1024,
      maxStorageBufferBindingSize: 2 * 1024 * 1024 * 1024,
      maxComputeWorkgroupsPerDimension: 65535,
      maxComputeWorkgroupSizeX: 1024,
      maxComputeWorkgroupSizeY: 1024,
      maxComputeWorkgroupSizeZ: 64,
      maxComputeInvocationsPerWorkgroup: 1024,
      supportsFloat16: false,
      supportsFloat64: true,
      supportsTimestampQuery: true,
      supportsIndirectDispatch: false,
    };
  }

  get gpuDevice(): GPUDevice | null {
    return this._gpuDevice;
  }

  get memoryPool(): MemoryPool {
    if (!this._initialized) {
      throw new Error('Device not initialized');
    }
    return this._memoryPool!;
  }

  get defaultStream(): Stream {
    if (!this._initialized) {
      throw new Error('Device not initialized');
    }
    return this._defaultStream!;
  }

  /**
   * Get a stream from the pool.
   */
  getStream(): Stream {
    const available = this._streamPool.find(s => !s.inUse);
    if (available) {
      available.inUse = true;
      return available;
    }

    const stream = new Stream(this);
    stream.inUse = true;
    this._streamPool.push(stream);
    return stream;
  }

  /**
   * Return a stream to the pool.
   */
  returnStream(stream: Stream): void {
    stream.inUse = false;
  }

  /**
   * Synchronize all streams.
   */
  async synchronize(): Promise<void> {
    await this._defaultStream?.synchronize();
    await Promise.all(this._streamPool.map(s => s.synchronize()));
  }

  /**
   * Use this device as the current context.
   */
  use<T>(fn: () => T): T {
    Device._contextStack.push(Device._current!);
    Device._current = this;
    try {
      return fn();
    } finally {
      Device._current = Device._contextStack.pop() || null;
    }
  }

  /**
   * Use this device as the current context (async).
   */
  async useAsync<T>(fn: () => Promise<T>): Promise<T> {
    Device._contextStack.push(Device._current!);
    Device._current = this;
    try {
      return await fn();
    } finally {
      Device._current = Device._contextStack.pop() || null;
    }
  }

  toString(): string {
    return `Device(${this.deviceType}, id=${this.deviceId})`;
  }
}

// ============================================================================
// Memory Management
// ============================================================================

export interface MemoryBlock {
  buffer: ArrayBuffer | GPUBuffer;
  size: number;
  type: MemoryType;
  device: Device;
  isFree: boolean;
  refCount: number;
  createdAt: number;
  lastAccessed: number;
}

export class MemoryPool {
  private static readonly SIZE_CLASSES = [
    64, 128, 256, 512, 1024, 2048, 4096, 8192, 16384,
    32768, 65536, 131072, 262144, 524288, 1048576,
    2097152, 4194304, 8388608, 16777216, 33554432,
  ];

  private readonly device: Device;
  private readonly freeLists: Map<number, MemoryBlock[]> = new Map();
  private readonly largeBlocks: MemoryBlock[] = [];
  private readonly blocks: Map<ArrayBuffer | GPUBuffer, MemoryBlock> = new Map();

  // Statistics
  private _totalAllocated = 0;
  private _totalFreed = 0;
  private _peakUsage = 0;
  private _allocationCount = 0;
  private _cacheHits = 0;
  private _cacheMisses = 0;

  constructor(device: Device) {
    this.device = device;

    for (const size of MemoryPool.SIZE_CLASSES) {
      this.freeLists.set(size, []);
    }
  }

  /**
   * Allocate a memory block.
   */
  allocate(
    size: number,
    type: MemoryType = MemoryType.ARRAY_BUFFER,
    alignment: number = 64,
    zeroFill: boolean = false
  ): MemoryBlock {
    this._allocationCount++;

    // Round up to alignment
    const alignedSize = Math.ceil(size / alignment) * alignment;

    // Try to find in free list
    let block = this._findFreeBlock(alignedSize, type);

    if (block) {
      this._cacheHits++;
      block.isFree = false;
      block.refCount = 1;
      block.lastAccessed = Date.now();
    } else {
      this._cacheMisses++;
      block = this._allocateNew(alignedSize, type);
    }

    if (zeroFill && block.buffer instanceof ArrayBuffer) {
      new Uint8Array(block.buffer).fill(0);
    }

    this._totalAllocated += block.size;
    this._peakUsage = Math.max(this._peakUsage, this.currentUsage);

    return block;
  }

  private _findFreeBlock(size: number, type: MemoryType): MemoryBlock | null {
    // Check size-class free lists
    for (const sizeClass of MemoryPool.SIZE_CLASSES) {
      if (sizeClass >= size) {
        const freeList = this.freeLists.get(sizeClass);
        if (freeList && freeList.length > 0) {
          const block = freeList.pop()!;
          if (block.type === type) {
            return block;
          }
          // Put it back if wrong type
          freeList.push(block);
        }
      }
    }

    // Check large blocks
    for (let i = 0; i < this.largeBlocks.length; i++) {
      const block = this.largeBlocks[i];
      if (block.size >= size && block.type === type) {
        this.largeBlocks.splice(i, 1);
        return block;
      }
    }

    return null;
  }

  private _allocateNew(size: number, type: MemoryType): MemoryBlock {
    let buffer: ArrayBuffer | GPUBuffer;

    switch (type) {
      case MemoryType.ARRAY_BUFFER:
        buffer = new ArrayBuffer(size);
        break;

      case MemoryType.SHARED_ARRAY_BUFFER:
        buffer = new SharedArrayBuffer(size);
        break;

      case MemoryType.GPU_BUFFER:
        if (!this.device.gpuDevice) {
          throw new Error('GPU device not available');
        }
        buffer = this.device.gpuDevice.createBuffer({
          size,
          usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST,
          mappedAtCreation: false,
        });
        break;

      default:
        buffer = new ArrayBuffer(size);
    }

    const block: MemoryBlock = {
      buffer,
      size,
      type,
      device: this.device,
      isFree: false,
      refCount: 1,
      createdAt: Date.now(),
      lastAccessed: Date.now(),
    };

    this.blocks.set(buffer, block);
    return block;
  }

  /**
   * Free a memory block (returns to pool).
   */
  free(block: MemoryBlock): void {
    block.refCount--;
    if (block.refCount <= 0) {
      block.isFree = true;
      this._totalFreed += block.size;
      this._returnToPool(block);
    }
  }

  private _returnToPool(block: MemoryBlock): void {
    // Find appropriate size class
    for (const sizeClass of MemoryPool.SIZE_CLASSES) {
      if (block.size <= sizeClass) {
        this.freeLists.get(sizeClass)!.push(block);
        return;
      }
    }

    // Large block
    this.largeBlocks.push(block);
  }

  get currentUsage(): number {
    return this._totalAllocated - this._totalFreed;
  }

  getStats(): {
    totalAllocated: number;
    totalFreed: number;
    currentUsage: number;
    peakUsage: number;
    allocationCount: number;
    cacheHits: number;
    cacheMisses: number;
    cacheHitRate: number;
  } {
    return {
      totalAllocated: this._totalAllocated,
      totalFreed: this._totalFreed,
      currentUsage: this.currentUsage,
      peakUsage: this._peakUsage,
      allocationCount: this._allocationCount,
      cacheHits: this._cacheHits,
      cacheMisses: this._cacheMisses,
      cacheHitRate: this._cacheHits / Math.max(1, this._allocationCount),
    };
  }

  /**
   * Trim unused memory.
   */
  trim(targetSize?: number): number {
    let released = 0;
    const target = targetSize ?? this.currentUsage;

    // Release from large blocks first
    while (this.largeBlocks.length > 0 && this.currentUsage > target) {
      const block = this.largeBlocks.pop()!;
      released += block.size;
      this.blocks.delete(block.buffer);

      if (block.buffer instanceof GPUBuffer) {
        block.buffer.destroy();
      }
    }

    // Release from size-class pools
    for (const sizeClass of [...MemoryPool.SIZE_CLASSES].reverse()) {
      const freeList = this.freeLists.get(sizeClass)!;
      while (freeList.length > 0 && this.currentUsage > target) {
        const block = freeList.pop()!;
        released += block.size;
        this.blocks.delete(block.buffer);

        if (block.buffer instanceof GPUBuffer) {
          block.buffer.destroy();
        }
      }
    }

    return released;
  }
}

// ============================================================================
// Execution Streams
// ============================================================================

export class Event {
  private _timestamp: number | null = null;
  private _completed = false;
  private _resolvers: (() => void)[] = [];

  readonly device: Device;

  constructor(device?: Device) {
    this.device = device ?? Device.getDefault();
  }

  /**
   * Record the event.
   */
  record(stream?: Stream): void {
    this._timestamp = performance.now();
  }

  /**
   * Mark the event as completed.
   */
  complete(): void {
    this._completed = true;
    for (const resolve of this._resolvers) {
      resolve();
    }
    this._resolvers = [];
  }

  /**
   * Wait for the event to complete.
   */
  async synchronize(): Promise<void> {
    if (this._completed) return;

    return new Promise((resolve) => {
      this._resolvers.push(resolve);
    });
  }

  /**
   * Check if the event has completed.
   */
  query(): boolean {
    return this._completed;
  }

  /**
   * Get elapsed time in milliseconds.
   */
  elapsedTime(endEvent: Event): number {
    if (this._timestamp === null || endEvent._timestamp === null) {
      throw new Error('Events must be recorded first');
    }
    return endEvent._timestamp - this._timestamp;
  }
}

export enum StreamPriority {
  LOW = 0,
  NORMAL = 1,
  HIGH = 2,
}

interface StreamCommand<T = unknown> {
  fn: () => Promise<T>;
  resolve: (value: T) => void;
  reject: (error: Error) => void;
  event?: Event;
  priority: number;
}

export class Stream {
  readonly device: Device;
  readonly isDefault: boolean;
  readonly priority: StreamPriority;

  inUse = false;

  private _commandQueue: StreamCommand[] = [];
  private _processing = false;
  private _pendingPromises: Promise<unknown>[] = [];

  constructor(
    device?: Device,
    isDefault: boolean = false,
    priority: StreamPriority = StreamPriority.NORMAL
  ) {
    this.device = device ?? Device.getDefault();
    this.isDefault = isDefault;
    this.priority = priority;
  }

  /**
   * Enqueue a function for execution.
   */
  enqueue<T>(
    fn: () => Promise<T>,
    event?: Event
  ): Promise<T> {
    return new Promise((resolve, reject) => {
      const command: StreamCommand<T> = {
        fn,
        resolve: resolve as (value: unknown) => void,
        reject,
        event,
        priority: -this.priority,
      };

      this._commandQueue.push(command);
      this._processQueue();
    });
  }

  private async _processQueue(): Promise<void> {
    if (this._processing) return;
    this._processing = true;

    while (this._commandQueue.length > 0) {
      // Sort by priority
      this._commandQueue.sort((a, b) => a.priority - b.priority);

      const command = this._commandQueue.shift()!;

      try {
        const result = await command.fn();
        command.resolve(result);

        if (command.event) {
          command.event.complete();
        }
      } catch (error) {
        command.reject(error as Error);
      }
    }

    this._processing = false;
  }

  /**
   * Record an event.
   */
  recordEvent(event?: Event): Event {
    const e = event ?? new Event(this.device);
    e.record(this);
    return e;
  }

  /**
   * Wait for an event.
   */
  async waitEvent(event: Event): Promise<void> {
    await this.enqueue(() => event.synchronize());
  }

  /**
   * Synchronize the stream.
   */
  async synchronize(): Promise<void> {
    await Promise.all(this._pendingPromises);
    this._pendingPromises = [];
  }
}

// ============================================================================
// Profiling
// ============================================================================

export interface ProfileEvent {
  name: string;
  category: string;
  startTime: number;
  endTime: number;
  durationMs: number;
  device: string;
  stream: string;
  metadata: Record<string, unknown>;
  memoryAllocated?: number;
  memoryFreed?: number;
}

export class Profiler {
  private static _current: Profiler | null = null;

  readonly enabled: boolean;
  readonly recordMemory: boolean;

  private _events: ProfileEvent[] = [];
  private _startTime = 0;

  constructor(
    enabled: boolean = true,
    recordMemory: boolean = true
  ) {
    this.enabled = enabled;
    this.recordMemory = recordMemory;
  }

  static getCurrent(): Profiler | null {
    return this._current;
  }

  /**
   * Start profiling.
   */
  start(): this {
    Profiler._current = this;
    this._startTime = performance.now();
    return this;
  }

  /**
   * Stop profiling.
   */
  stop(): this {
    Profiler._current = null;
    return this;
  }

  /**
   * Trace a function execution.
   */
  async trace<T>(
    name: string,
    fn: () => Promise<T>,
    category: string = 'default',
    metadata: Record<string, unknown> = {}
  ): Promise<T> {
    if (!this.enabled) {
      return fn();
    }

    const start = performance.now();
    const startMemory = this._getMemory();

    try {
      return await fn();
    } finally {
      const end = performance.now();
      const endMemory = this._getMemory();

      this._events.push({
        name,
        category,
        startTime: start - this._startTime,
        endTime: end - this._startTime,
        durationMs: end - start,
        device: Device.getDefault().toString(),
        stream: 'default',
        metadata,
        memoryAllocated: Math.max(0, endMemory - startMemory),
        memoryFreed: Math.max(0, startMemory - endMemory),
      });
    }
  }

  /**
   * Trace a synchronous function.
   */
  traceSync<T>(
    name: string,
    fn: () => T,
    category: string = 'default',
    metadata: Record<string, unknown> = {}
  ): T {
    if (!this.enabled) {
      return fn();
    }

    const start = performance.now();

    try {
      return fn();
    } finally {
      const end = performance.now();

      this._events.push({
        name,
        category,
        startTime: start - this._startTime,
        endTime: end - this._startTime,
        durationMs: end - start,
        device: Device.getDefault().toString(),
        stream: 'default',
        metadata,
      });
    }
  }

  private _getMemory(): number {
    if (typeof performance !== 'undefined' && 'memory' in performance) {
      return (performance as Performance & { memory: { usedJSHeapSize: number } }).memory.usedJSHeapSize;
    }
    return 0;
  }

  /**
   * Get profiling summary.
   */
  summary(): string {
    const lines: string[] = [
      '='.repeat(60),
      'AETHELRED PROFILER SUMMARY',
      '='.repeat(60),
    ];

    // Group by category
    const byCategory = new Map<string, ProfileEvent[]>();
    for (const event of this._events) {
      if (!byCategory.has(event.category)) {
        byCategory.set(event.category, []);
      }
      byCategory.get(event.category)!.push(event);
    }

    const totalTime = this._events.reduce((sum, e) => sum + e.durationMs, 0);

    for (const [category, events] of byCategory) {
      lines.push(`\n${category.toUpperCase()}`);
      lines.push('-'.repeat(40));

      // Aggregate by name
      const byName = new Map<string, number[]>();
      for (const e of events) {
        if (!byName.has(e.name)) {
          byName.set(e.name, []);
        }
        byName.get(e.name)!.push(e.durationMs);
      }

      const sorted = [...byName.entries()].sort((a, b) => {
        const sumA = a[1].reduce((s, v) => s + v, 0);
        const sumB = b[1].reduce((s, v) => s + v, 0);
        return sumB - sumA;
      });

      for (const [name, times] of sorted) {
        const total = times.reduce((s, v) => s + v, 0);
        const avg = total / times.length;
        const pct = (total / totalTime) * 100;

        lines.push(
          `  ${name.padEnd(30)} ` +
          `calls=${times.length.toString().padStart(4)}  ` +
          `total=${total.toFixed(2).padStart(8)}ms  ` +
          `avg=${avg.toFixed(2).padStart(8)}ms  ` +
          `(${pct.toFixed(1).padStart(5)}%)`
        );
      }
    }

    lines.push('\n' + '='.repeat(60));
    lines.push(`Total profiled time: ${totalTime.toFixed(2)}ms`);
    lines.push(`Total events: ${this._events.length}`);

    return lines.join('\n');
  }

  /**
   * Export to Chrome Trace format.
   */
  exportChromeTrace(): object {
    const traceEvents = this._events.map((event) => ({
      name: event.name,
      cat: event.category,
      ph: 'X',
      ts: event.startTime * 1000,
      dur: event.durationMs * 1000,
      pid: 1,
      tid: 1,
      args: event.metadata,
    }));

    return {
      traceEvents,
      displayTimeUnit: 'ms',
    };
  }

  /**
   * Export to JSON.
   */
  exportJSON(): object {
    return {
      events: this._events,
      summary: {
        totalEvents: this._events.length,
        totalTimeMs: this._events.reduce((sum, e) => sum + e.durationMs, 0),
        categories: [...new Set(this._events.map(e => e.category))],
      },
    };
  }
}

// ============================================================================
// Runtime
// ============================================================================

export interface RuntimeOptions {
  devices?: Device[];
  defaultDevice?: Device;
  enableProfiling?: boolean;
  workerPoolSize?: number;
}

export class Runtime {
  private static _instance: Runtime | null = null;
  private static _initialized = false;

  private _devices: Device[] = [];
  private _defaultDevice: Device | null = null;
  private _profiler: Profiler | null = null;
  private _workerPool: Worker[] = [];

  static getInstance(): Runtime {
    if (!this._instance) {
      this._instance = new Runtime();
    }
    return this._instance;
  }

  /**
   * Initialize the runtime.
   */
  static async initialize(options: RuntimeOptions = {}): Promise<Runtime> {
    const runtime = this.getInstance();

    if (this._initialized) {
      return runtime;
    }

    // Enumerate devices
    if (options.devices) {
      runtime._devices = options.devices;
    } else {
      runtime._devices = await Device.enumerateDevices();
    }

    // Set default device
    if (options.defaultDevice) {
      runtime._defaultDevice = options.defaultDevice;
    } else if (runtime._devices.length > 0) {
      // Prefer GPU over CPU
      const gpu = runtime._devices.find(d =>
        d.deviceType === DeviceType.GPU_WEBGPU ||
        d.deviceType === DeviceType.GPU_WEBGL
      );
      runtime._defaultDevice = gpu ?? runtime._devices[0];
    }

    // Initialize devices
    for (const device of runtime._devices) {
      await device.initialize();
    }

    // Enable profiling
    if (options.enableProfiling) {
      runtime._profiler = new Profiler(true);
      runtime._profiler.start();
    }

    this._initialized = true;
    return runtime;
  }

  get devices(): Device[] {
    return this._devices;
  }

  get defaultDevice(): Device | null {
    return this._defaultDevice;
  }

  get profiler(): Profiler | null {
    return this._profiler;
  }

  /**
   * Shutdown the runtime.
   */
  async shutdown(): Promise<void> {
    for (const device of this._devices) {
      await device.synchronize();
    }

    for (const worker of this._workerPool) {
      worker.terminate();
    }

    if (this._profiler) {
      this._profiler.stop();
    }

    Runtime._initialized = false;
  }
}

// ============================================================================
// Decorators
// ============================================================================

/**
 * Profile a method.
 */
export function profile(category: string = 'default') {
  return function (
    target: unknown,
    propertyKey: string,
    descriptor: PropertyDescriptor
  ) {
    const original = descriptor.value;

    descriptor.value = async function (...args: unknown[]) {
      const profiler = Profiler.getCurrent();
      if (!profiler) {
        return original.apply(this, args);
      }

      return profiler.trace(
        propertyKey,
        () => original.apply(this, args),
        category
      );
    };

    return descriptor;
  };
}

// ============================================================================
// Exports
// ============================================================================

export const runtime = Runtime;
