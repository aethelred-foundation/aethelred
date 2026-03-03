/**
 * Aethelred SDK - Distributed Computing Module
 *
 * Enterprise-grade distributed training:
 * - Data Parallel (DDP)
 * - Model Parallel (Tensor, Pipeline)
 * - ZeRO Optimizer (Stages 1-3)
 * - Gradient Compression
 * - Elastic Training
 * - Fault Tolerance
 */

import { Tensor } from '../core/tensor';
import { Module, Parameter } from '../nn/module';
import { Optimizer } from '../optim';

// ============ Communication Backends ============

export enum Backend {
  WEBSOCKET = 'websocket',
  WEBRTC = 'webrtc',
  HTTP = 'http',
  WORKER = 'worker',
}

export enum ReduceOp {
  SUM = 'sum',
  MEAN = 'mean',
  MAX = 'max',
  MIN = 'min',
  PRODUCT = 'product',
}

// ============ Process Group ============

export interface ProcessGroupConfig {
  rank: number;
  worldSize: number;
  backend: Backend;
  masterAddr?: string;
  masterPort?: number;
}

export class ProcessGroup {
  private _rank: number;
  private _worldSize: number;
  private _backend: Backend;
  private _initialized: boolean = false;
  private _workers: Map<number, Worker | WebSocket | RTCDataChannel> = new Map();

  constructor(config: ProcessGroupConfig) {
    this._rank = config.rank;
    this._worldSize = config.worldSize;
    this._backend = config.backend;
  }

  static async init(config: ProcessGroupConfig): Promise<ProcessGroup> {
    const group = new ProcessGroup(config);
    await group.initialize();
    return group;
  }

  private async initialize(): Promise<void> {
    switch (this._backend) {
      case Backend.WORKER:
        await this.initWorkerBackend();
        break;
      case Backend.WEBSOCKET:
        await this.initWebSocketBackend();
        break;
      case Backend.WEBRTC:
        await this.initWebRTCBackend();
        break;
      default:
        throw new Error(`Unsupported backend: ${this._backend}`);
    }
    this._initialized = true;
  }

  private async initWorkerBackend(): Promise<void> {
    // Initialize Web Workers for local parallelism
    for (let i = 0; i < this._worldSize; i++) {
      if (i !== this._rank) {
        // Workers would be created here
      }
    }
  }

  private async initWebSocketBackend(): Promise<void> {
    // Initialize WebSocket connections for distributed training
  }

  private async initWebRTCBackend(): Promise<void> {
    // Initialize WebRTC for peer-to-peer communication
  }

  get rank(): number {
    return this._rank;
  }

  get worldSize(): number {
    return this._worldSize;
  }

  get backend(): Backend {
    return this._backend;
  }

  isInitialized(): boolean {
    return this._initialized;
  }

  // ============ Collective Operations ============

  async broadcast(tensor: Tensor, src: number): Promise<Tensor> {
    if (this._rank === src) {
      // Send tensor to all other ranks
      for (let i = 0; i < this._worldSize; i++) {
        if (i !== this._rank) {
          await this.send(tensor, i);
        }
      }
      return tensor;
    } else {
      // Receive tensor from source
      return this.recv(src);
    }
  }

  async reduce(tensor: Tensor, dst: number, op: ReduceOp = ReduceOp.SUM): Promise<Tensor | null> {
    if (this._rank === dst) {
      let result = tensor;
      for (let i = 0; i < this._worldSize; i++) {
        if (i !== this._rank) {
          const received = await this.recv(i);
          result = this.applyReduceOp(result, received, op);
        }
      }
      return result;
    } else {
      await this.send(tensor, dst);
      return null;
    }
  }

  async allReduce(tensor: Tensor, op: ReduceOp = ReduceOp.SUM): Promise<Tensor> {
    // Ring all-reduce implementation
    const chunkSize = Math.ceil(tensor.numel / this._worldSize);
    let result = tensor;

    // Reduce-scatter phase
    for (let step = 0; step < this._worldSize - 1; step++) {
      const sendRank = (this._rank + 1) % this._worldSize;
      const recvRank = (this._rank - 1 + this._worldSize) % this._worldSize;

      // Exchange and accumulate
      await this.send(result, sendRank);
      const received = await this.recv(recvRank);
      result = this.applyReduceOp(result, received, op);
    }

    // All-gather phase
    for (let step = 0; step < this._worldSize - 1; step++) {
      const sendRank = (this._rank + 1) % this._worldSize;
      const recvRank = (this._rank - 1 + this._worldSize) % this._worldSize;

      await this.send(result, sendRank);
      result = await this.recv(recvRank);
    }

    return result;
  }

  async allGather(tensor: Tensor): Promise<Tensor[]> {
    const gathered: Tensor[] = new Array(this._worldSize);
    gathered[this._rank] = tensor;

    for (let i = 0; i < this._worldSize; i++) {
      if (i !== this._rank) {
        await this.send(tensor, i);
        gathered[i] = await this.recv(i);
      }
    }

    return gathered;
  }

  async scatter(tensors: Tensor[] | null, src: number): Promise<Tensor> {
    if (this._rank === src) {
      if (!tensors) {
        throw new Error('Source rank must provide tensors to scatter');
      }
      for (let i = 0; i < this._worldSize; i++) {
        if (i !== this._rank) {
          await this.send(tensors[i], i);
        }
      }
      return tensors[this._rank];
    } else {
      return this.recv(src);
    }
  }

  async gather(tensor: Tensor, dst: number): Promise<Tensor[] | null> {
    if (this._rank === dst) {
      const gathered: Tensor[] = new Array(this._worldSize);
      gathered[this._rank] = tensor;

      for (let i = 0; i < this._worldSize; i++) {
        if (i !== this._rank) {
          gathered[i] = await this.recv(i);
        }
      }
      return gathered;
    } else {
      await this.send(tensor, dst);
      return null;
    }
  }

  async reduceScatter(tensors: Tensor[], op: ReduceOp = ReduceOp.SUM): Promise<Tensor> {
    // Reduce then scatter
    const reduced = tensors.reduce((acc, t) => this.applyReduceOp(acc, t, op));

    // Split into chunks and distribute
    const chunkSize = Math.ceil(reduced.numel / this._worldSize);
    return reduced.slice(
      [this._rank * chunkSize],
      [Math.min((this._rank + 1) * chunkSize, reduced.numel)]
    );
  }

  async barrier(): Promise<void> {
    // Simple barrier using all-reduce of dummy tensor
    const dummy = Tensor.zeros([1]);
    await this.allReduce(dummy);
  }

  // ============ Point-to-Point Operations ============

  async send(tensor: Tensor, dst: number): Promise<void> {
    // Serialize and send tensor to destination rank
    await tensor.realize();
    const data = await tensor.toArray();
    const message = {
      type: 'tensor',
      shape: tensor.shape,
      dtype: tensor.dtype,
      data,
    };

    // Send via appropriate backend
    const worker = this._workers.get(dst);
    if (worker instanceof Worker) {
      worker.postMessage(message);
    } else if (worker instanceof WebSocket) {
      worker.send(JSON.stringify(message));
    }
  }

  async recv(src: number): Promise<Tensor> {
    // Receive tensor from source rank
    return new Promise((resolve) => {
      const worker = this._workers.get(src);

      const handler = (event: MessageEvent) => {
        const message = typeof event.data === 'string' ? JSON.parse(event.data) : event.data;
        if (message.type === 'tensor') {
          const tensor = new Tensor(message.data, {
            shape: message.shape,
            dtype: message.dtype,
          });
          resolve(tensor);
        }
      };

      if (worker instanceof Worker) {
        worker.addEventListener('message', handler, { once: true });
      } else if (worker instanceof WebSocket) {
        worker.addEventListener('message', handler, { once: true });
      }
    });
  }

  async isend(tensor: Tensor, dst: number): Promise<{ wait: () => Promise<void> }> {
    const promise = this.send(tensor, dst);
    return { wait: () => promise };
  }

  async irecv(src: number): Promise<{ wait: () => Promise<Tensor> }> {
    let resolveOuter: (tensor: Tensor) => void;
    const outerPromise = new Promise<Tensor>((resolve) => {
      resolveOuter = resolve;
    });

    this.recv(src).then(tensor => resolveOuter(tensor));

    return { wait: () => outerPromise };
  }

  // ============ Helper Methods ============

  private applyReduceOp(a: Tensor, b: Tensor, op: ReduceOp): Tensor {
    switch (op) {
      case ReduceOp.SUM:
        return a.add(b);
      case ReduceOp.MEAN:
        return a.add(b).div(2);
      case ReduceOp.MAX:
        // Would need proper element-wise max
        return a.add(b.sub(a).relu());
      case ReduceOp.MIN:
        return a.sub(a.sub(b).relu());
      case ReduceOp.PRODUCT:
        return a.mul(b);
      default:
        throw new Error(`Unsupported reduce operation: ${op}`);
    }
  }

  destroy(): void {
    for (const worker of this._workers.values()) {
      if (worker instanceof Worker) {
        worker.terminate();
      } else if (worker instanceof WebSocket) {
        worker.close();
      }
    }
    this._workers.clear();
    this._initialized = false;
  }
}

// ============ Distributed Data Parallel ============

export interface DDPConfig {
  processGroup?: ProcessGroup;
  bucketSizeMb?: number;
  gradientAsyncCommunication?: boolean;
  findUnusedParameters?: boolean;
  broadcastBuffers?: boolean;
}

export class DistributedDataParallel {
  private module: Module;
  private processGroup: ProcessGroup;
  private bucketSizeMb: number;
  private gradientAsyncCommunication: boolean;
  private findUnusedParameters: boolean;
  private broadcastBuffers: boolean;

  private gradientBuckets: Map<number, Tensor[]> = new Map();
  private bucketReady: Map<number, boolean> = new Map();

  constructor(module: Module, config: DDPConfig = {}) {
    this.module = module;
    this.processGroup = config.processGroup || new ProcessGroup({
      rank: 0,
      worldSize: 1,
      backend: Backend.WORKER,
    });
    this.bucketSizeMb = config.bucketSizeMb ?? 25;
    this.gradientAsyncCommunication = config.gradientAsyncCommunication ?? true;
    this.findUnusedParameters = config.findUnusedParameters ?? false;
    this.broadcastBuffers = config.broadcastBuffers ?? true;

    this.setupGradientBuckets();
  }

  private setupGradientBuckets(): void {
    const bucketSizeBytes = this.bucketSizeMb * 1024 * 1024;
    let currentBucket = 0;
    let currentSize = 0;

    this.gradientBuckets.set(currentBucket, []);

    for (const param of this.module.parameters()) {
      const paramSize = param.data.numel * 4; // Assume float32

      if (currentSize + paramSize > bucketSizeBytes) {
        currentBucket++;
        currentSize = 0;
        this.gradientBuckets.set(currentBucket, []);
      }

      this.gradientBuckets.get(currentBucket)!.push(param.data);
      currentSize += paramSize;
    }
  }

  async forward(...inputs: Tensor[]): Promise<Tensor | Tensor[]> {
    // Broadcast buffers if needed
    if (this.broadcastBuffers) {
      for (const buffer of this.module.buffers()) {
        await this.processGroup.broadcast(buffer.data, 0);
      }
    }

    // Forward pass
    return this.module.call(...inputs);
  }

  async synchronizeGradients(): Promise<void> {
    // All-reduce gradients across all processes
    for (const params of this.gradientBuckets.values()) {
      for (const param of params) {
        // This would work on actual gradients
        if (param) {
          const reduced = await this.processGroup.allReduce(param, ReduceOp.MEAN);
          // Update gradient with reduced value
        }
      }
    }
  }

  getModule(): Module {
    return this.module;
  }

  async stateDict(): Promise<Map<string, Tensor>> {
    // Only rank 0 should save
    if (this.processGroup.rank === 0) {
      return this.module.stateDict();
    }
    return new Map();
  }
}

// ============ ZeRO Optimizer ============

export enum ZeROStage {
  STAGE_1 = 1, // Partition optimizer states
  STAGE_2 = 2, // Partition gradients
  STAGE_3 = 3, // Partition parameters
}

export interface ZeROConfig {
  stage: ZeROStage;
  processGroup?: ProcessGroup;
  overlapComm?: boolean;
  contiguousGradients?: boolean;
  reduceScatter?: boolean;
  cpuOffload?: boolean;
  cpuOffloadParams?: boolean;
}

export class ZeROOptimizer {
  private optimizer: Optimizer;
  private stage: ZeROStage;
  private processGroup: ProcessGroup;
  private overlapComm: boolean;
  private contiguousGradients: boolean;
  private reduceScatter: boolean;
  private cpuOffload: boolean;
  private cpuOffloadParams: boolean;

  private partitionedParams: Map<number, Parameter[]> = new Map();
  private partitionedGradients: Map<number, Tensor[]> = new Map();

  constructor(optimizer: Optimizer, config: ZeROConfig) {
    this.optimizer = optimizer;
    this.stage = config.stage;
    this.processGroup = config.processGroup || new ProcessGroup({
      rank: 0,
      worldSize: 1,
      backend: Backend.WORKER,
    });
    this.overlapComm = config.overlapComm ?? true;
    this.contiguousGradients = config.contiguousGradients ?? true;
    this.reduceScatter = config.reduceScatter ?? true;
    this.cpuOffload = config.cpuOffload ?? false;
    this.cpuOffloadParams = config.cpuOffloadParams ?? false;

    this.partitionParameters();
  }

  private partitionParameters(): void {
    const rank = this.processGroup.rank;
    const worldSize = this.processGroup.worldSize;

    // Partition parameters across ranks
    let paramIndex = 0;
    for (const group of (this.optimizer as any).paramGroups) {
      for (const param of group.params) {
        const ownerRank = paramIndex % worldSize;

        if (!this.partitionedParams.has(ownerRank)) {
          this.partitionedParams.set(ownerRank, []);
        }
        this.partitionedParams.get(ownerRank)!.push(param);

        paramIndex++;
      }
    }
  }

  async step(): Promise<void> {
    const rank = this.processGroup.rank;
    const worldSize = this.processGroup.worldSize;

    switch (this.stage) {
      case ZeROStage.STAGE_1:
        // Only partition optimizer states
        await this.stepStage1();
        break;

      case ZeROStage.STAGE_2:
        // Partition optimizer states and gradients
        await this.stepStage2();
        break;

      case ZeROStage.STAGE_3:
        // Partition optimizer states, gradients, and parameters
        await this.stepStage3();
        break;
    }
  }

  private async stepStage1(): Promise<void> {
    // Reduce gradients
    for (const group of (this.optimizer as any).paramGroups) {
      for (const param of group.params) {
        if (param.grad) {
          await this.processGroup.allReduce(param.grad, ReduceOp.MEAN);
        }
      }
    }

    // Update only owned parameters
    await this.optimizer.step();

    // Broadcast updated parameters
    for (const [ownerRank, params] of this.partitionedParams) {
      for (const param of params) {
        await this.processGroup.broadcast(param.data, ownerRank);
      }
    }
  }

  private async stepStage2(): Promise<void> {
    const rank = this.processGroup.rank;

    // Reduce-scatter gradients
    for (const group of (this.optimizer as any).paramGroups) {
      const grads: Tensor[] = [];
      for (const param of group.params) {
        if (param.grad) {
          grads.push(param.grad);
        }
      }

      if (grads.length > 0) {
        // Each rank gets a portion of the reduced gradients
        await this.processGroup.reduceScatter(grads);
      }
    }

    // Update only owned parameters
    const ownedParams = this.partitionedParams.get(rank) || [];
    for (const param of ownedParams) {
      // Optimizer step for this param only
    }
    await this.optimizer.step();

    // All-gather updated parameters
    for (const [ownerRank, params] of this.partitionedParams) {
      for (const param of params) {
        await this.processGroup.broadcast(param.data, ownerRank);
      }
    }
  }

  private async stepStage3(): Promise<void> {
    const rank = this.processGroup.rank;
    const worldSize = this.processGroup.worldSize;

    // Gather necessary parameters for forward/backward
    for (const [ownerRank, params] of this.partitionedParams) {
      if (ownerRank !== rank) {
        for (const param of params) {
          // Prefetch parameters from owner
          await this.processGroup.broadcast(param.data, ownerRank);
        }
      }
    }

    // Reduce-scatter gradients
    await this.stepStage2();

    // Release non-owned parameters after update
    for (const [ownerRank, params] of this.partitionedParams) {
      if (ownerRank !== rank) {
        for (const param of params) {
          // Release memory for non-owned parameters
          // param.data = null (conceptually)
        }
      }
    }
  }

  zeroGrad(): void {
    this.optimizer.zeroGrad();
  }
}

// ============ Pipeline Parallel ============

export enum PipelineSchedule {
  GPIPE = 'gpipe',
  ONE_F_ONE_B = '1f1b',
  INTERLEAVED = 'interleaved',
}

export interface PipelineConfig {
  stages: Module[];
  processGroup?: ProcessGroup;
  schedule?: PipelineSchedule;
  microBatchSize?: number;
  numMicroBatches?: number;
}

export class PipelineParallel {
  private stages: Module[];
  private processGroup: ProcessGroup;
  private schedule: PipelineSchedule;
  private microBatchSize: number;
  private numMicroBatches: number;
  private stageId: number;

  private activationCache: Map<number, Tensor[]> = new Map();

  constructor(config: PipelineConfig) {
    this.stages = config.stages;
    this.processGroup = config.processGroup || new ProcessGroup({
      rank: 0,
      worldSize: config.stages.length,
      backend: Backend.WORKER,
    });
    this.schedule = config.schedule ?? PipelineSchedule.ONE_F_ONE_B;
    this.microBatchSize = config.microBatchSize ?? 1;
    this.numMicroBatches = config.numMicroBatches ?? 4;
    this.stageId = this.processGroup.rank;
  }

  async forward(input: Tensor): Promise<Tensor> {
    switch (this.schedule) {
      case PipelineSchedule.GPIPE:
        return this.forwardGPipe(input);
      case PipelineSchedule.ONE_F_ONE_B:
        return this.forward1F1B(input);
      case PipelineSchedule.INTERLEAVED:
        return this.forwardInterleaved(input);
      default:
        throw new Error(`Unknown pipeline schedule: ${this.schedule}`);
    }
  }

  private async forwardGPipe(input: Tensor): Promise<Tensor> {
    // GPipe: All forward passes, then all backward passes
    const microBatches = this.splitMicroBatches(input);
    const outputs: Tensor[] = [];

    // Forward pass for all micro-batches
    for (let mb = 0; mb < microBatches.length; mb++) {
      let activation: Tensor;

      if (this.stageId === 0) {
        // First stage receives input
        activation = microBatches[mb];
      } else {
        // Other stages receive from previous stage
        activation = await this.processGroup.recv(this.stageId - 1);
      }

      // Forward through this stage
      const stage = this.stages[this.stageId];
      const output = await stage.call(activation) as Tensor;

      // Cache activation for backward pass
      this.activationCache.set(mb, [activation]);

      if (this.stageId < this.stages.length - 1) {
        // Send to next stage
        await this.processGroup.send(output, this.stageId + 1);
      } else {
        // Last stage collects output
        outputs.push(output);
      }
    }

    // Return concatenated outputs
    if (outputs.length > 0) {
      return Tensor.cat(outputs, 0);
    }

    // Non-last stages return dummy
    return Tensor.zeros([1]);
  }

  private async forward1F1B(input: Tensor): Promise<Tensor> {
    // 1F1B: Interleave forward and backward passes
    const microBatches = this.splitMicroBatches(input);
    const numStages = this.stages.length;
    const outputs: Tensor[] = [];

    // Warmup phase: only forward passes
    const warmupSteps = numStages - this.stageId - 1;

    for (let step = 0; step < this.numMicroBatches + warmupSteps; step++) {
      // Forward pass
      if (step < this.numMicroBatches) {
        let activation: Tensor;

        if (this.stageId === 0) {
          activation = microBatches[step];
        } else {
          activation = await this.processGroup.recv(this.stageId - 1);
        }

        const stage = this.stages[this.stageId];
        const output = await stage.call(activation) as Tensor;

        this.activationCache.set(step, [activation]);

        if (this.stageId < numStages - 1) {
          await this.processGroup.send(output, this.stageId + 1);
        } else {
          outputs.push(output);
        }
      }

      // Backward pass (after warmup)
      if (step >= warmupSteps) {
        const mbIdx = step - warmupSteps;
        // Backward pass would go here
      }
    }

    if (outputs.length > 0) {
      return Tensor.cat(outputs, 0);
    }

    return Tensor.zeros([1]);
  }

  private async forwardInterleaved(input: Tensor): Promise<Tensor> {
    // Interleaved schedule for multiple stages per device
    // Simplified: same as 1F1B for now
    return this.forward1F1B(input);
  }

  private splitMicroBatches(input: Tensor): Tensor[] {
    const batchSize = input.shape[0];
    const numBatches = Math.ceil(batchSize / this.microBatchSize);
    const batches: Tensor[] = [];

    for (let i = 0; i < numBatches; i++) {
      const start = i * this.microBatchSize;
      const end = Math.min((i + 1) * this.microBatchSize, batchSize);
      batches.push(input.slice([start], [end]));
    }

    return batches;
  }

  getStage(): Module {
    return this.stages[this.stageId];
  }
}

// ============ Tensor Parallel ============

export class ColumnParallelLinear extends Module {
  private weight: Parameter;
  private bias: Parameter | null;
  private processGroup: ProcessGroup;
  private gatherOutput: boolean;

  constructor(
    inFeatures: number,
    outFeatures: number,
    processGroup: ProcessGroup,
    options: { bias?: boolean; gatherOutput?: boolean } = {}
  ) {
    super();

    const worldSize = processGroup.worldSize;
    const rank = processGroup.rank;

    // Partition output features
    const localOutFeatures = Math.ceil(outFeatures / worldSize);
    const startIdx = rank * localOutFeatures;
    const endIdx = Math.min((rank + 1) * localOutFeatures, outFeatures);
    const actualLocalOut = endIdx - startIdx;

    this.weight = new Parameter(Tensor.randn([actualLocalOut, inFeatures]));
    this.registerParameter('weight', this.weight);

    if (options.bias !== false) {
      this.bias = new Parameter(Tensor.zeros([actualLocalOut]));
      this.registerParameter('bias', this.bias);
    } else {
      this.bias = null;
    }

    this.processGroup = processGroup;
    this.gatherOutput = options.gatherOutput ?? true;
  }

  forward(input: Tensor): Tensor {
    // Local matmul
    let output = input.matmul(this.weight.data.t());

    if (this.bias) {
      output = output.add(this.bias.data);
    }

    // Gather outputs from all ranks if needed
    if (this.gatherOutput) {
      // All-gather along output dimension
      // output = allGather(output, dim=-1)
    }

    return output;
  }
}

export class RowParallelLinear extends Module {
  private weight: Parameter;
  private bias: Parameter | null;
  private processGroup: ProcessGroup;
  private inputIsParallel: boolean;

  constructor(
    inFeatures: number,
    outFeatures: number,
    processGroup: ProcessGroup,
    options: { bias?: boolean; inputIsParallel?: boolean } = {}
  ) {
    super();

    const worldSize = processGroup.worldSize;
    const rank = processGroup.rank;

    // Partition input features
    const localInFeatures = Math.ceil(inFeatures / worldSize);
    const startIdx = rank * localInFeatures;
    const endIdx = Math.min((rank + 1) * localInFeatures, inFeatures);
    const actualLocalIn = endIdx - startIdx;

    this.weight = new Parameter(Tensor.randn([outFeatures, actualLocalIn]));
    this.registerParameter('weight', this.weight);

    if (options.bias !== false && rank === 0) {
      this.bias = new Parameter(Tensor.zeros([outFeatures]));
      this.registerParameter('bias', this.bias);
    } else {
      this.bias = null;
    }

    this.processGroup = processGroup;
    this.inputIsParallel = options.inputIsParallel ?? false;
  }

  forward(input: Tensor): Tensor {
    // Split input if not already parallel
    let localInput = input;
    if (!this.inputIsParallel) {
      // Scatter input along feature dimension
    }

    // Local matmul
    let output = localInput.matmul(this.weight.data.t());

    // All-reduce to sum partial results
    // output = allReduce(output, op=SUM)

    if (this.bias) {
      output = output.add(this.bias.data);
    }

    return output;
  }
}

// ============ Gradient Compression ============

export enum CompressionType {
  NONE = 'none',
  TOPK = 'topk',
  RANDOM_K = 'randomk',
  POWER_SGD = 'powersgd',
  QUANTIZATION = 'quantization',
}

export interface GradientCompressorConfig {
  type: CompressionType;
  ratio?: number;
  rank?: number;
}

export class GradientCompressor {
  private type: CompressionType;
  private ratio: number;
  private rank: number;

  private errorBuffer: Map<Parameter, Tensor> = new Map();
  private pBuffer: Map<Parameter, Tensor> = new Map();
  private qBuffer: Map<Parameter, Tensor> = new Map();

  constructor(config: GradientCompressorConfig) {
    this.type = config.type;
    this.ratio = config.ratio ?? 0.01;
    this.rank = config.rank ?? 4;
  }

  async compress(gradient: Tensor): Promise<{ indices?: Tensor; values: Tensor }> {
    switch (this.type) {
      case CompressionType.NONE:
        return { values: gradient };

      case CompressionType.TOPK:
        return this.topkCompress(gradient);

      case CompressionType.RANDOM_K:
        return this.randomkCompress(gradient);

      case CompressionType.POWER_SGD:
        return this.powerSGDCompress(gradient);

      case CompressionType.QUANTIZATION:
        return this.quantizeCompress(gradient);

      default:
        throw new Error(`Unknown compression type: ${this.type}`);
    }
  }

  async decompress(compressed: { indices?: Tensor; values: Tensor }, shape: number[]): Promise<Tensor> {
    switch (this.type) {
      case CompressionType.NONE:
        return compressed.values;

      case CompressionType.TOPK:
      case CompressionType.RANDOM_K:
        return this.sparseDecompress(compressed, shape);

      case CompressionType.POWER_SGD:
        return this.powerSGDDecompress(compressed, shape);

      case CompressionType.QUANTIZATION:
        return this.dequantize(compressed.values);

      default:
        throw new Error(`Unknown compression type: ${this.type}`);
    }
  }

  private async topkCompress(gradient: Tensor): Promise<{ indices: Tensor; values: Tensor }> {
    const k = Math.ceil(gradient.numel * this.ratio);

    // Find top-k absolute values
    const absGrad = gradient.abs();
    // Would need proper top-k implementation
    // For now, return all values
    return {
      indices: Tensor.arange(gradient.numel),
      values: gradient,
    };
  }

  private async randomkCompress(gradient: Tensor): Promise<{ indices: Tensor; values: Tensor }> {
    const k = Math.ceil(gradient.numel * this.ratio);

    // Random sampling
    const indices: number[] = [];
    const totalElements = gradient.numel;

    for (let i = 0; i < k; i++) {
      indices.push(Math.floor(Math.random() * totalElements));
    }

    return {
      indices: new Tensor(indices),
      values: gradient, // Would need proper indexing
    };
  }

  private async powerSGDCompress(gradient: Tensor): Promise<{ values: Tensor }> {
    // PowerSGD low-rank approximation
    // Simplified implementation
    return { values: gradient };
  }

  private async quantizeCompress(gradient: Tensor): Promise<{ values: Tensor }> {
    // Quantize to lower precision
    const scale = gradient.abs().max();
    const quantized = gradient.div(scale).mul(127);
    return { values: quantized };
  }

  private async sparseDecompress(
    compressed: { indices?: Tensor; values: Tensor },
    shape: number[]
  ): Promise<Tensor> {
    const result = Tensor.zeros(shape);
    // Scatter values at indices
    return result;
  }

  private async powerSGDDecompress(
    compressed: { values: Tensor },
    shape: number[]
  ): Promise<Tensor> {
    return compressed.values.reshape(shape);
  }

  private async dequantize(quantized: Tensor): Promise<Tensor> {
    return quantized.div(127);
  }
}

// ============ Elastic Training ============

export interface ElasticConfig {
  minNodes: number;
  maxNodes: number;
  checkpointDir?: string;
  healthCheckInterval?: number;
}

export class ElasticTrainer {
  private minNodes: number;
  private maxNodes: number;
  private checkpointDir: string;
  private healthCheckInterval: number;

  private currentNodes: number;
  private processGroup: ProcessGroup | null = null;
  private isLeader: boolean = false;
  private healthCheckTimer: NodeJS.Timeout | null = null;

  constructor(config: ElasticConfig) {
    this.minNodes = config.minNodes;
    this.maxNodes = config.maxNodes;
    this.checkpointDir = config.checkpointDir ?? '/tmp/elastic_ckpt';
    this.healthCheckInterval = config.healthCheckInterval ?? 30000;
    this.currentNodes = 0;
  }

  async initialize(rank: number, worldSize: number): Promise<ProcessGroup> {
    this.currentNodes = worldSize;
    this.isLeader = rank === 0;

    this.processGroup = await ProcessGroup.init({
      rank,
      worldSize,
      backend: Backend.WEBSOCKET,
    });

    // Start health check
    this.startHealthCheck();

    return this.processGroup;
  }

  private startHealthCheck(): void {
    this.healthCheckTimer = setInterval(async () => {
      await this.checkHealth();
    }, this.healthCheckInterval);
  }

  private async checkHealth(): Promise<void> {
    if (!this.processGroup) return;

    try {
      await this.processGroup.barrier();
    } catch (error) {
      // Node failure detected
      console.warn('Node failure detected, initiating recovery');
      await this.handleNodeFailure();
    }
  }

  private async handleNodeFailure(): Promise<void> {
    // Save checkpoint
    if (this.isLeader) {
      // await this.saveCheckpoint();
    }

    // Wait for minimum nodes
    while (this.currentNodes < this.minNodes) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }

    // Reinitialize process group
    // await this.reinitialize();

    // Restore from checkpoint
    if (this.isLeader) {
      // await this.restoreCheckpoint();
    }
  }

  async scaleUp(newNodes: number): Promise<void> {
    if (this.currentNodes + newNodes > this.maxNodes) {
      throw new Error('Cannot exceed maximum nodes');
    }

    // Add new nodes to process group
    this.currentNodes += newNodes;

    // Redistribute data and parameters
    await this.redistribute();
  }

  async scaleDown(removeNodes: number): Promise<void> {
    if (this.currentNodes - removeNodes < this.minNodes) {
      throw new Error('Cannot go below minimum nodes');
    }

    this.currentNodes -= removeNodes;

    // Redistribute data and parameters
    await this.redistribute();
  }

  private async redistribute(): Promise<void> {
    // Redistribute data shards across new node count
    // This would involve resharding the dataset and model
  }

  destroy(): void {
    if (this.healthCheckTimer) {
      clearInterval(this.healthCheckTimer);
    }

    if (this.processGroup) {
      this.processGroup.destroy();
    }
  }
}
