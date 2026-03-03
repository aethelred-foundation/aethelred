/**
 * Aethelred SDK - Neural Network Module System
 *
 * PyTorch-compatible nn.Module API with:
 * - Hierarchical module composition
 * - Parameter management
 * - Forward/backward hooks
 * - State dict serialization
 * - Training/evaluation modes
 */

import { Tensor, DType } from '../core/tensor';
import { Device, DeviceType, Runtime } from '../core/runtime';

// ============ Parameter ============

export class Parameter {
  private _tensor: Tensor;
  private _name: string = '';
  private _requiresGrad: boolean;

  constructor(data: Tensor | number[] | number[][], requiresGrad: boolean = true) {
    if (data instanceof Tensor) {
      this._tensor = data;
    } else {
      this._tensor = new Tensor(data as number[] | number[][], { requiresGrad });
    }
    this._requiresGrad = requiresGrad;
    this._tensor.requiresGrad = requiresGrad;
  }

  get data(): Tensor {
    return this._tensor;
  }

  set data(value: Tensor) {
    this._tensor = value;
    this._tensor.requiresGrad = this._requiresGrad;
  }

  get grad(): Tensor | null {
    return this._tensor.grad;
  }

  get shape(): number[] {
    return this._tensor.shape;
  }

  get dtype(): DType {
    return this._tensor.dtype;
  }

  get name(): string {
    return this._name;
  }

  set name(value: string) {
    this._name = value;
  }

  get requiresGrad(): boolean {
    return this._requiresGrad;
  }

  zeroGrad(): void {
    this._tensor.zeroGrad();
  }

  async toDevice(device: Device): Promise<void> {
    this._tensor = await this._tensor.to(device);
  }

  detach(): Tensor {
    return this._tensor.detach();
  }

  clone(): Parameter {
    return new Parameter(this._tensor.clone(), this._requiresGrad);
  }
}

// ============ Buffer ============

export class Buffer {
  private _tensor: Tensor;
  private _name: string = '';
  private _persistent: boolean;

  constructor(data: Tensor | number[] | number[][], persistent: boolean = true) {
    if (data instanceof Tensor) {
      this._tensor = data;
    } else {
      this._tensor = new Tensor(data as number[] | number[][], { requiresGrad: false });
    }
    this._persistent = persistent;
  }

  get data(): Tensor {
    return this._tensor;
  }

  set data(value: Tensor) {
    this._tensor = value;
  }

  get name(): string {
    return this._name;
  }

  set name(value: string) {
    this._name = value;
  }

  get persistent(): boolean {
    return this._persistent;
  }

  async toDevice(device: Device): Promise<void> {
    this._tensor = await this._tensor.to(device);
  }
}

// ============ Hook Types ============

export type ForwardPreHook = (module: Module, input: Tensor[]) => Tensor[] | void;
export type ForwardHook = (module: Module, input: Tensor[], output: Tensor) => Tensor | void;
export type BackwardHook = (module: Module, gradInput: Tensor[], gradOutput: Tensor[]) => Tensor[] | void;

export interface HookHandle {
  id: string;
  remove: () => void;
}

// ============ Module Base Class ============

export abstract class Module {
  private _name: string = '';
  private _training: boolean = true;
  private _parameters: Map<string, Parameter> = new Map();
  private _buffers: Map<string, Buffer> = new Map();
  private _modules: Map<string, Module> = new Map();
  private _forwardPreHooks: Map<string, ForwardPreHook> = new Map();
  private _forwardHooks: Map<string, ForwardHook> = new Map();
  private _backwardHooks: Map<string, BackwardHook> = new Map();
  private _hookIdCounter: number = 0;

  constructor() { }

  // ============ Abstract Methods ============

  abstract forward(...inputs: Tensor[]): Tensor | Tensor[];

  // ============ Call ============

  async call(...inputs: Tensor[]): Promise<Tensor | Tensor[]> {
    // Execute pre-forward hooks
    let processedInputs = inputs;
    for (const hook of this._forwardPreHooks.values()) {
      const result = hook(this, processedInputs);
      if (result) processedInputs = result;
    }

    // Forward pass
    let output = this.forward(...processedInputs);

    // Realize lazy tensors
    if (output instanceof Tensor) {
      await output.realize();
    } else if (Array.isArray(output)) {
      await Promise.all(output.map(t => t.realize()));
    }

    // Execute post-forward hooks
    for (const hook of this._forwardHooks.values()) {
      if (output instanceof Tensor) {
        const result = hook(this, processedInputs, output);
        if (result) output = result;
      }
    }

    return output;
  }

  // ============ Properties ============

  get name(): string {
    return this._name || this.constructor.name;
  }

  set name(value: string) {
    this._name = value;
  }

  get training(): boolean {
    return this._training;
  }

  // ============ Training Mode ============

  train(mode: boolean = true): this {
    this._training = mode;
    for (const module of this._modules.values()) {
      module.train(mode);
    }
    return this;
  }

  eval(): this {
    return this.train(false);
  }

  // ============ Parameter Registration ============

  protected registerParameter(name: string, param: Parameter | null): void {
    if (param === null) {
      this._parameters.delete(name);
    } else {
      param.name = `${this.name}.${name}`;
      this._parameters.set(name, param);
    }
  }

  protected registerBuffer(name: string, buffer: Buffer | null): void {
    if (buffer === null) {
      this._buffers.delete(name);
    } else {
      buffer.name = `${this.name}.${name}`;
      this._buffers.set(name, buffer);
    }
  }

  protected registerModule(name: string, module: Module | null): void {
    if (module === null) {
      this._modules.delete(name);
    } else {
      module.name = `${this.name}.${name}`;
      this._modules.set(name, module);
    }
  }

  // ============ Parameter Access ============

  *parameters(recurse: boolean = true): Generator<Parameter> {
    for (const param of this._parameters.values()) {
      yield param;
    }

    if (recurse) {
      for (const module of this._modules.values()) {
        yield* module.parameters(true);
      }
    }
  }

  *namedParameters(prefix: string = '', recurse: boolean = true): Generator<[string, Parameter]> {
    for (const [name, param] of this._parameters) {
      const fullName = prefix ? `${prefix}.${name}` : name;
      yield [fullName, param];
    }

    if (recurse) {
      for (const [name, module] of this._modules) {
        const fullName = prefix ? `${prefix}.${name}` : name;
        yield* module.namedParameters(fullName, true);
      }
    }
  }

  *buffers(recurse: boolean = true): Generator<Buffer> {
    for (const buffer of this._buffers.values()) {
      yield buffer;
    }

    if (recurse) {
      for (const module of this._modules.values()) {
        yield* module.buffers(true);
      }
    }
  }

  *namedBuffers(prefix: string = '', recurse: boolean = true): Generator<[string, Buffer]> {
    for (const [name, buffer] of this._buffers) {
      const fullName = prefix ? `${prefix}.${name}` : name;
      yield [fullName, buffer];
    }

    if (recurse) {
      for (const [name, module] of this._modules) {
        const fullName = prefix ? `${prefix}.${name}` : name;
        yield* module.namedBuffers(fullName, true);
      }
    }
  }

  *modules(recurse: boolean = true): Generator<Module> {
    yield this;

    for (const module of this._modules.values()) {
      if (recurse) {
        yield* module.modules(true);
      } else {
        yield module;
      }
    }
  }

  *namedModules(prefix: string = '', recurse: boolean = true): Generator<[string, Module]> {
    yield [prefix, this];

    for (const [name, module] of this._modules) {
      const fullName = prefix ? `${prefix}.${name}` : name;
      if (recurse) {
        yield* module.namedModules(fullName, true);
      } else {
        yield [fullName, module];
      }
    }
  }

  *children(): Generator<Module> {
    for (const module of this._modules.values()) {
      yield module;
    }
  }

  getParameter(name: string): Parameter | undefined {
    const parts = name.split('.');

    if (parts.length === 1) {
      return this._parameters.get(name);
    }

    const [first, ...rest] = parts;
    const submodule = this._modules.get(first);

    if (submodule) {
      return submodule.getParameter(rest.join('.'));
    }

    return undefined;
  }

  getBuffer(name: string): Buffer | undefined {
    const parts = name.split('.');

    if (parts.length === 1) {
      return this._buffers.get(name);
    }

    const [first, ...rest] = parts;
    const submodule = this._modules.get(first);

    if (submodule) {
      return submodule.getBuffer(rest.join('.'));
    }

    return undefined;
  }

  getSubmodule(name: string): Module | undefined {
    const parts = name.split('.');
    let current: Module = this;

    for (const part of parts) {
      const next = current._modules.get(part);
      if (!next) return undefined;
      current = next;
    }

    return current;
  }

  // ============ Hooks ============

  registerForwardPreHook(hook: ForwardPreHook): HookHandle {
    const id = `hook_${this._hookIdCounter++}`;
    this._forwardPreHooks.set(id, hook);

    return {
      id,
      remove: () => this._forwardPreHooks.delete(id),
    };
  }

  registerForwardHook(hook: ForwardHook): HookHandle {
    const id = `hook_${this._hookIdCounter++}`;
    this._forwardHooks.set(id, hook);

    return {
      id,
      remove: () => this._forwardHooks.delete(id),
    };
  }

  registerBackwardHook(hook: BackwardHook): HookHandle {
    const id = `hook_${this._hookIdCounter++}`;
    this._backwardHooks.set(id, hook);

    return {
      id,
      remove: () => this._backwardHooks.delete(id),
    };
  }

  // ============ State Dict ============

  stateDict(): Map<string, Tensor> {
    const state = new Map<string, Tensor>();

    for (const [name, param] of this.namedParameters()) {
      state.set(name, param.data);
    }

    for (const [name, buffer] of this.namedBuffers()) {
      if (buffer.persistent) {
        state.set(name, buffer.data);
      }
    }

    return state;
  }

  loadStateDict(stateDict: Map<string, Tensor>, strict: boolean = true): { missing: string[]; unexpected: string[] } {
    const missing: string[] = [];
    const unexpected: string[] = [];

    const currentKeys = new Set<string>();

    for (const [name, param] of this.namedParameters()) {
      currentKeys.add(name);
      const value = stateDict.get(name);

      if (value) {
        param.data = value;
      } else {
        missing.push(name);
      }
    }

    for (const [name, buffer] of this.namedBuffers()) {
      if (buffer.persistent) {
        currentKeys.add(name);
        const value = stateDict.get(name);

        if (value) {
          buffer.data = value;
        } else {
          missing.push(name);
        }
      }
    }

    for (const key of stateDict.keys()) {
      if (!currentKeys.has(key)) {
        unexpected.push(key);
      }
    }

    if (strict && (missing.length > 0 || unexpected.length > 0)) {
      throw new Error(
        `Error loading state dict: missing keys: [${missing}], unexpected keys: [${unexpected}]`
      );
    }

    return { missing, unexpected };
  }

  // ============ Device Transfer ============

  async to(device: Device): Promise<this> {
    for (const param of this.parameters()) {
      await param.toDevice(device);
    }

    for (const buffer of this.buffers()) {
      await buffer.toDevice(device);
    }

    return this;
  }

  async cpu(): Promise<this> {
    const cpuDevice = Runtime.getInstance().defaultDevice;
    if (!cpuDevice) {
      throw new Error('No default CPU device available — call Runtime.initialize() first');
    }
    return this.to(cpuDevice);
  }

  async gpu(): Promise<this> {
    const gpuDevice = Runtime.getInstance().devices.find(
      d => d.deviceType === DeviceType.GPU_WEBGPU || d.deviceType === DeviceType.GPU_WEBGL
    );

    if (!gpuDevice) {
      throw new Error('No GPU device available');
    }

    return this.to(gpuDevice);
  }

  // ============ Gradient Management ============

  zeroGrad(): void {
    for (const param of this.parameters()) {
      param.zeroGrad();
    }
  }

  requiresGrad_(requires: boolean = true): this {
    for (const param of this.parameters()) {
      param.data.requiresGrad = requires;
    }
    return this;
  }

  // ============ Parameter Count ============

  numParameters(onlyTrainable: boolean = false): number {
    let count = 0;

    for (const param of this.parameters()) {
      if (!onlyTrainable || param.requiresGrad) {
        count += param.data.numel;
      }
    }

    return count;
  }

  // ============ Apply Function ============

  apply(fn: (module: Module) => void): this {
    for (const module of this.modules()) {
      fn(module);
    }
    return this;
  }

  // ============ Extra Repr ============

  extraRepr(): string {
    return '';
  }

  toString(): string {
    const lines: string[] = [];
    const extra = this.extraRepr();

    lines.push(`${this.constructor.name}(${extra})`);

    for (const [name, module] of this._modules) {
      const moduleStr = module.toString().split('\n');
      lines.push(`  (${name}): ${moduleStr[0]}`);

      for (let i = 1; i < moduleStr.length; i++) {
        lines.push(`  ${moduleStr[i]}`);
      }
    }

    return lines.join('\n');
  }
}

// ============ Module Exports ============

export default Module;
