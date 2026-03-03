/**
 * Aethelred SDK - Neural Network Containers
 *
 * Container modules for composing neural networks:
 * - Sequential
 * - ModuleList
 * - ModuleDict
 * - ParameterList
 * - ParameterDict
 */

import { Tensor } from '../core/tensor';
import { Module, Parameter } from './module';

// ============ Sequential ============

export class Sequential extends Module {
  private _moduleList: Module[] = [];

  constructor(...modules: Module[]) {
    super();

    for (let i = 0; i < modules.length; i++) {
      this.addModule(String(i), modules[i]);
    }
  }

  addModule(name: string, module: Module): void {
    this._moduleList.push(module);
    this.registerModule(name, module);
  }

  forward(input: Tensor): Tensor {
    let output = input;

    for (const module of this._moduleList) {
      output = module.forward(output) as Tensor;
    }

    return output;
  }

  get length(): number {
    return this._moduleList.length;
  }

  get(index: number): Module {
    return this._moduleList[index];
  }

  *[Symbol.iterator](): Iterator<Module> {
    for (const module of this._moduleList) {
      yield module;
    }
  }

  append(module: Module): this {
    const index = this._moduleList.length;
    this.addModule(String(index), module);
    return this;
  }

  insert(index: number, module: Module): void {
    this._moduleList.splice(index, 0, module);
    // Re-register all modules
    for (let i = 0; i < this._moduleList.length; i++) {
      this.registerModule(String(i), this._moduleList[i]);
    }
  }

  pop(): Module {
    const module = this._moduleList.pop();
    if (!module) {
      throw new Error('Cannot pop from empty Sequential');
    }
    // Re-register modules
    for (let i = 0; i < this._moduleList.length; i++) {
      this.registerModule(String(i), this._moduleList[i]);
    }
    return module;
  }
}

// ============ ModuleList ============

export class ModuleList extends Module {
  private _moduleItems: Module[] = [];

  constructor(modules?: Module[]) {
    super();

    if (modules) {
      for (const module of modules) {
        this.append(module);
      }
    }
  }

  forward(..._inputs: Tensor[]): Tensor | Tensor[] {
    throw new Error('ModuleList does not implement forward(). Iterate over modules manually.');
  }

  append(module: Module): this {
    const index = this._moduleItems.length;
    this._moduleItems.push(module);
    this.registerModule(String(index), module);
    return this;
  }

  extend(modules: Module[]): this {
    for (const module of modules) {
      this.append(module);
    }
    return this;
  }

  insert(index: number, module: Module): void {
    this._moduleItems.splice(index, 0, module);
    // Re-register all modules
    for (let i = 0; i < this._moduleItems.length; i++) {
      this.registerModule(String(i), this._moduleItems[i]);
    }
  }

  get(index: number): Module {
    if (index < 0) {
      index = this._moduleItems.length + index;
    }
    return this._moduleItems[index];
  }

  set(index: number, module: Module): void {
    if (index < 0) {
      index = this._moduleItems.length + index;
    }
    this._moduleItems[index] = module;
    this.registerModule(String(index), module);
  }

  get length(): number {
    return this._moduleItems.length;
  }

  *[Symbol.iterator](): Iterator<Module> {
    for (const module of this._moduleItems) {
      yield module;
    }
  }

  slice(start?: number, end?: number): Module[] {
    return this._moduleItems.slice(start, end);
  }

  pop(): Module {
    const module = this._moduleItems.pop();
    if (!module) {
      throw new Error('Cannot pop from empty ModuleList');
    }
    return module;
  }
}

// ============ ModuleDict ============

export class ModuleDict extends Module {
  private _moduleMap: Map<string, Module> = new Map();

  constructor(modules?: Record<string, Module> | [string, Module][]) {
    super();

    if (modules) {
      if (Array.isArray(modules)) {
        for (const [key, module] of modules) {
          this.set(key, module);
        }
      } else {
        for (const [key, module] of Object.entries(modules)) {
          this.set(key, module);
        }
      }
    }
  }

  forward(..._inputs: Tensor[]): Tensor | Tensor[] {
    throw new Error('ModuleDict does not implement forward(). Access modules by key.');
  }

  get(key: string): Module | undefined {
    return this._moduleMap.get(key);
  }

  set(key: string, module: Module): void {
    this._moduleMap.set(key, module);
    this.registerModule(key, module);
  }

  delete(key: string): boolean {
    const result = this._moduleMap.delete(key);
    if (result) {
      this.registerModule(key, null);
    }
    return result;
  }

  has(key: string): boolean {
    return this._moduleMap.has(key);
  }

  keys(): IterableIterator<string> {
    return this._moduleMap.keys();
  }

  values(): IterableIterator<Module> {
    return this._moduleMap.values();
  }

  entries(): IterableIterator<[string, Module]> {
    return this._moduleMap.entries();
  }

  get size(): number {
    return this._moduleMap.size;
  }

  *[Symbol.iterator](): Iterator<[string, Module]> {
    for (const entry of this._moduleMap) {
      yield entry;
    }
  }

  clear(): void {
    for (const key of this._moduleMap.keys()) {
      this.registerModule(key, null);
    }
    this._moduleMap.clear();
  }

  update(modules: Record<string, Module> | [string, Module][]): void {
    if (Array.isArray(modules)) {
      for (const [key, module] of modules) {
        this.set(key, module);
      }
    } else {
      for (const [key, module] of Object.entries(modules)) {
        this.set(key, module);
      }
    }
  }

  pop(key: string): Module | undefined {
    const module = this._moduleMap.get(key);
    if (module) {
      this.delete(key);
    }
    return module;
  }
}

// ============ ParameterList ============

export class ParameterList extends Module {
  private _parameterItems: Parameter[] = [];

  constructor(parameters?: Parameter[]) {
    super();

    if (parameters) {
      for (const param of parameters) {
        this.append(param);
      }
    }
  }

  forward(..._inputs: Tensor[]): Tensor | Tensor[] {
    throw new Error('ParameterList does not implement forward().');
  }

  append(param: Parameter): this {
    const index = this._parameterItems.length;
    this._parameterItems.push(param);
    this.registerParameter(String(index), param);
    return this;
  }

  extend(params: Parameter[]): this {
    for (const param of params) {
      this.append(param);
    }
    return this;
  }

  get(index: number): Parameter {
    if (index < 0) {
      index = this._parameterItems.length + index;
    }
    return this._parameterItems[index];
  }

  set(index: number, param: Parameter): void {
    if (index < 0) {
      index = this._parameterItems.length + index;
    }
    this._parameterItems[index] = param;
    this.registerParameter(String(index), param);
  }

  get length(): number {
    return this._parameterItems.length;
  }

  *[Symbol.iterator](): Iterator<Parameter> {
    for (const param of this._parameterItems) {
      yield param;
    }
  }
}

// ============ ParameterDict ============

export class ParameterDict extends Module {
  private _parameterMap: Map<string, Parameter> = new Map();

  constructor(parameters?: Record<string, Parameter> | [string, Parameter][]) {
    super();

    if (parameters) {
      if (Array.isArray(parameters)) {
        for (const [key, param] of parameters) {
          this.set(key, param);
        }
      } else {
        for (const [key, param] of Object.entries(parameters)) {
          this.set(key, param);
        }
      }
    }
  }

  forward(..._inputs: Tensor[]): Tensor | Tensor[] {
    throw new Error('ParameterDict does not implement forward().');
  }

  get(key: string): Parameter | undefined {
    return this._parameterMap.get(key);
  }

  set(key: string, param: Parameter): void {
    this._parameterMap.set(key, param);
    this.registerParameter(key, param);
  }

  delete(key: string): boolean {
    const result = this._parameterMap.delete(key);
    if (result) {
      this.registerParameter(key, null);
    }
    return result;
  }

  has(key: string): boolean {
    return this._parameterMap.has(key);
  }

  keys(): IterableIterator<string> {
    return this._parameterMap.keys();
  }

  values(): IterableIterator<Parameter> {
    return this._parameterMap.values();
  }

  entries(): IterableIterator<[string, Parameter]> {
    return this._parameterMap.entries();
  }

  get size(): number {
    return this._parameterMap.size;
  }

  *[Symbol.iterator](): Iterator<[string, Parameter]> {
    for (const entry of this._parameterMap) {
      yield entry;
    }
  }

  clear(): void {
    for (const key of this._parameterMap.keys()) {
      this.registerParameter(key, null);
    }
    this._parameterMap.clear();
  }

  update(params: Record<string, Parameter> | [string, Parameter][]): void {
    if (Array.isArray(params)) {
      for (const [key, param] of params) {
        this.set(key, param);
      }
    } else {
      for (const [key, param] of Object.entries(params)) {
        this.set(key, param);
      }
    }
  }
}
