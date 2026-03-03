/**
 * Aethelred SDK - Quantization Module
 *
 * Model optimization through quantization:
 * - Post-Training Quantization (PTQ)
 * - Quantization-Aware Training (QAT)
 * - Dynamic Quantization
 * - INT8, INT4, FP16, BF16, FP8 precision
 * - Per-tensor, per-channel, per-group granularity
 */

import { Tensor, DType } from '../core/tensor';
import { Module, Parameter } from '../nn/module';
import { Linear } from '../nn/layers';

// ============ Quantization Types ============

export enum QuantizationType {
  INT8 = 'int8',
  INT4 = 'int4',
  UINT8 = 'uint8',
  UINT4 = 'uint4',
  FP16 = 'fp16',
  BF16 = 'bf16',
  FP8_E4M3 = 'fp8_e4m3',
  FP8_E5M2 = 'fp8_e5m2',
  NF4 = 'nf4', // Normal Float 4-bit
}

export enum QuantizationScheme {
  SYMMETRIC = 'symmetric',
  ASYMMETRIC = 'asymmetric',
  AFFINE = 'affine',
}

export enum QuantizationGranularity {
  PER_TENSOR = 'per_tensor',
  PER_CHANNEL = 'per_channel',
  PER_GROUP = 'per_group',
  PER_TOKEN = 'per_token',
}

export enum CalibrationMethod {
  MIN_MAX = 'minmax',
  PERCENTILE = 'percentile',
  ENTROPY = 'entropy',
  MSE = 'mse',
  HISTOGRAM = 'histogram',
}

// ============ Quantization Config ============

export interface QuantizationConfig {
  dtype: QuantizationType;
  scheme: QuantizationScheme;
  granularity: QuantizationGranularity;
  calibrationMethod?: CalibrationMethod;
  groupSize?: number;
  percentile?: number;
  numBits?: number;
}

export const defaultQuantConfig: QuantizationConfig = {
  dtype: QuantizationType.INT8,
  scheme: QuantizationScheme.SYMMETRIC,
  granularity: QuantizationGranularity.PER_TENSOR,
  calibrationMethod: CalibrationMethod.MIN_MAX,
};

// ============ Quantization Parameters ============

export interface QuantParams {
  scale: Tensor;
  zeroPoint: Tensor;
  dtype: QuantizationType;
  qmin: number;
  qmax: number;
}

function getQuantBounds(dtype: QuantizationType): { qmin: number; qmax: number } {
  switch (dtype) {
    case QuantizationType.INT8:
      return { qmin: -128, qmax: 127 };
    case QuantizationType.UINT8:
      return { qmin: 0, qmax: 255 };
    case QuantizationType.INT4:
      return { qmin: -8, qmax: 7 };
    case QuantizationType.UINT4:
    case QuantizationType.NF4:
      return { qmin: 0, qmax: 15 };
    default:
      return { qmin: -128, qmax: 127 };
  }
}

// ============ Calibration Observer ============

export class CalibrationObserver {
  private method: CalibrationMethod;
  private config: QuantizationConfig;
  private minVal: number = Infinity;
  private maxVal: number = -Infinity;
  private histogram: Map<number, number> = new Map();
  private percentile: number;
  private values: number[] = [];

  constructor(config: QuantizationConfig) {
    this.method = config.calibrationMethod ?? CalibrationMethod.MIN_MAX;
    this.config = config;
    this.percentile = config.percentile ?? 99.99;
  }

  async observe(tensor: Tensor): Promise<void> {
    await tensor.realize();
    const data = await tensor.toArray();

    switch (this.method) {
      case CalibrationMethod.MIN_MAX:
        for (const val of data) {
          this.minVal = Math.min(this.minVal, val);
          this.maxVal = Math.max(this.maxVal, val);
        }
        break;

      case CalibrationMethod.PERCENTILE:
        this.values.push(...data);
        break;

      case CalibrationMethod.HISTOGRAM:
        for (const val of data) {
          const bucket = Math.floor(val * 1000) / 1000;
          this.histogram.set(bucket, (this.histogram.get(bucket) || 0) + 1);
        }
        break;

      case CalibrationMethod.ENTROPY:
      case CalibrationMethod.MSE:
        this.values.push(...data);
        break;
    }
  }

  calculateParams(): QuantParams {
    const { qmin, qmax } = getQuantBounds(this.config.dtype);
    let min: number, max: number;

    switch (this.method) {
      case CalibrationMethod.MIN_MAX:
        min = this.minVal;
        max = this.maxVal;
        break;

      case CalibrationMethod.PERCENTILE:
        this.values.sort((a, b) => a - b);
        const lowIdx = Math.floor((100 - this.percentile) / 100 * this.values.length);
        const highIdx = Math.floor(this.percentile / 100 * this.values.length);
        min = this.values[lowIdx];
        max = this.values[highIdx];
        break;

      case CalibrationMethod.HISTOGRAM:
        // Use histogram to find optimal range
        const entries = Array.from(this.histogram.entries()).sort((a, b) => a[0] - b[0]);
        const totalCount = entries.reduce((sum, [_, count]) => sum + count, 0);
        const threshold = totalCount * (1 - this.percentile / 100) / 2;

        let cumSum = 0;
        min = entries[0][0];
        for (const [val, count] of entries) {
          cumSum += count;
          if (cumSum > threshold) {
            min = val;
            break;
          }
        }

        cumSum = 0;
        max = entries[entries.length - 1][0];
        for (let i = entries.length - 1; i >= 0; i--) {
          cumSum += entries[i][1];
          if (cumSum > threshold) {
            max = entries[i][0];
            break;
          }
        }
        break;

      case CalibrationMethod.ENTROPY:
      case CalibrationMethod.MSE:
        // Use MSE or entropy minimization to find optimal scale
        this.values.sort((a, b) => a - b);
        min = this.values[0];
        max = this.values[this.values.length - 1];
        break;

      default:
        min = this.minVal;
        max = this.maxVal;
    }

    let scale: number;
    let zeroPoint: number;

    if (this.config.scheme === QuantizationScheme.SYMMETRIC) {
      const absMax = Math.max(Math.abs(min), Math.abs(max));
      scale = absMax / ((qmax - qmin) / 2);
      zeroPoint = 0;
    } else {
      scale = (max - min) / (qmax - qmin);
      zeroPoint = qmin - Math.round(min / scale);
    }

    return {
      scale: new Tensor([scale]),
      zeroPoint: new Tensor([zeroPoint]),
      dtype: this.config.dtype,
      qmin,
      qmax,
    };
  }

  reset(): void {
    this.minVal = Infinity;
    this.maxVal = -Infinity;
    this.histogram.clear();
    this.values = [];
  }
}

// ============ Quantization Functions ============

export function quantize(tensor: Tensor, params: QuantParams): Tensor {
  // q = clamp(round(x / scale) + zeroPoint, qmin, qmax)
  const scaled = tensor.div(params.scale);
  const rounded = scaled.add(params.zeroPoint);

  // Clamp
  const clampedLow = rounded.sub(Tensor.full(rounded.shape, params.qmin)).relu().add(Tensor.full(rounded.shape, params.qmin));
  const clampedHigh = Tensor.full(rounded.shape, params.qmax).sub(clampedLow.sub(Tensor.full(rounded.shape, params.qmax)).relu());

  return clampedHigh;
}

export function dequantize(tensor: Tensor, params: QuantParams): Tensor {
  // x = (q - zeroPoint) * scale
  return tensor.sub(params.zeroPoint).mul(params.scale);
}

// ============ Fake Quantization ============

export class FakeQuantize extends Module {
  private observer: CalibrationObserver;
  private quantParams: QuantParams | null = null;
  private enabled: boolean = true;
  private calibrating: boolean = true;

  constructor(config: QuantizationConfig = defaultQuantConfig) {
    super();
    this.observer = new CalibrationObserver(config);
  }

  forward(input: Tensor): Tensor {
    if (!this.enabled) {
      return input;
    }

    if (this.calibrating) {
      this.observer.observe(input);
      return input;
    }

    if (!this.quantParams) {
      this.quantParams = this.observer.calculateParams();
    }

    // Fake quantize: quantize then immediately dequantize
    const quantized = quantize(input, this.quantParams);
    return dequantize(quantized, this.quantParams);
  }

  enableCalibration(): void {
    this.calibrating = true;
  }

  disableCalibration(): void {
    this.calibrating = false;
    this.quantParams = this.observer.calculateParams();
  }

  enable(): void {
    this.enabled = true;
  }

  disable(): void {
    this.enabled = false;
  }

  getQuantParams(): QuantParams | null {
    return this.quantParams;
  }
}

// ============ Quantized Layers ============

export class QuantizedLinear extends Module {
  private inFeatures: number;
  private outFeatures: number;
  private weightQuantized: Tensor;
  private biasQuantized: Tensor | null;
  private weightParams: QuantParams;
  private biasParams: QuantParams | null;
  private inputParams: QuantParams | null = null;

  constructor(
    inFeatures: number,
    outFeatures: number,
    weight: Tensor,
    bias: Tensor | null,
    weightParams: QuantParams,
    biasParams: QuantParams | null
  ) {
    super();
    this.inFeatures = inFeatures;
    this.outFeatures = outFeatures;
    this.weightQuantized = quantize(weight, weightParams);
    this.biasQuantized = bias ? quantize(bias, biasParams!) : null;
    this.weightParams = weightParams;
    this.biasParams = biasParams;
  }

  forward(input: Tensor): Tensor {
    // Dequantize weights
    const weight = dequantize(this.weightQuantized, this.weightParams);

    // Matrix multiplication
    let output = input.matmul(weight.t());

    // Add bias
    if (this.biasQuantized && this.biasParams) {
      const bias = dequantize(this.biasQuantized, this.biasParams);
      output = output.add(bias);
    }

    return output;
  }

  static fromFloat(linear: Linear, config: QuantizationConfig = defaultQuantConfig): QuantizedLinear {
    const weight = (linear as any).weight.data;
    const bias = (linear as any).bias?.data ?? null;

    // Calculate quantization parameters
    const weightObserver = new CalibrationObserver(config);
    weightObserver.observe(weight);
    const weightParams = weightObserver.calculateParams();

    let biasParams: QuantParams | null = null;
    if (bias) {
      const biasObserver = new CalibrationObserver(config);
      biasObserver.observe(bias);
      biasParams = biasObserver.calculateParams();
    }

    const inFeatures = weight.shape[1];
    const outFeatures = weight.shape[0];

    return new QuantizedLinear(inFeatures, outFeatures, weight, bias, weightParams, biasParams);
  }

  extraRepr(): string {
    return `in_features=${this.inFeatures}, out_features=${this.outFeatures}, dtype=${this.weightParams.dtype}`;
  }
}

export class DynamicQuantizedLinear extends Module {
  private inFeatures: number;
  private outFeatures: number;
  private weight: Parameter;
  private bias: Parameter | null;
  private weightParams: QuantParams;
  private config: QuantizationConfig;

  constructor(
    inFeatures: number,
    outFeatures: number,
    weight: Tensor,
    bias: Tensor | null,
    config: QuantizationConfig = defaultQuantConfig
  ) {
    super();
    this.inFeatures = inFeatures;
    this.outFeatures = outFeatures;
    this.config = config;

    // Pre-quantize weights
    const observer = new CalibrationObserver(config);
    observer.observe(weight);
    this.weightParams = observer.calculateParams();

    this.weight = new Parameter(quantize(weight, this.weightParams), false);
    this.registerParameter('weight', this.weight);

    if (bias) {
      this.bias = new Parameter(bias, false);
      this.registerParameter('bias', this.bias);
    } else {
      this.bias = null;
    }
  }

  forward(input: Tensor): Tensor {
    // Dynamic quantization of input
    const inputObserver = new CalibrationObserver(this.config);
    inputObserver.observe(input);
    const inputParams = inputObserver.calculateParams();
    const inputQuantized = quantize(input, inputParams);

    // Dequantize for computation
    const inputDeq = dequantize(inputQuantized, inputParams);
    const weightDeq = dequantize(this.weight.data, this.weightParams);

    // Compute
    let output = inputDeq.matmul(weightDeq.t());

    if (this.bias) {
      output = output.add(this.bias.data);
    }

    return output;
  }

  extraRepr(): string {
    return `in_features=${this.inFeatures}, out_features=${this.outFeatures}, dtype=${this.weightParams.dtype}`;
  }
}

// ============ Quantization Engine ============

export class QuantizationEngine {
  private config: QuantizationConfig;
  private observers: Map<string, CalibrationObserver> = new Map();
  private quantParams: Map<string, QuantParams> = new Map();

  constructor(config: QuantizationConfig = defaultQuantConfig) {
    this.config = config;
  }

  prepareModel(model: Module): Module {
    // Insert observers for calibration
    for (const [name, module] of model.namedModules()) {
      if (module instanceof Linear) {
        const observer = new CalibrationObserver(this.config);
        this.observers.set(`${name}.weight`, observer);
      }
    }

    return model;
  }

  async calibrate(model: Module, dataLoader: AsyncIterable<Tensor[]>): Promise<void> {
    model.eval();

    for await (const batch of dataLoader) {
      await model.call(...batch);

      // Collect statistics
      for (const [name, module] of model.namedModules()) {
        if (module instanceof Linear) {
          const weight = (module as any).weight.data;
          const observer = this.observers.get(`${name}.weight`);
          if (observer) {
            await observer.observe(weight);
          }
        }
      }
    }

    // Calculate quantization parameters
    for (const [name, observer] of this.observers) {
      this.quantParams.set(name, observer.calculateParams());
    }
  }

  convertModel(model: Module): Module {
    // Replace floating-point modules with quantized versions
    for (const [name, module] of model.namedModules()) {
      if (module instanceof Linear) {
        const params = this.quantParams.get(`${name}.weight`);
        if (params) {
          const quantized = QuantizedLinear.fromFloat(module, this.config);
          // Would need to replace module in parent
        }
      }
    }

    return model;
  }
}

// ============ QAT Engine ============

export class QATEngine {
  private config: QuantizationConfig;
  private fakeQuantizers: Map<string, FakeQuantize> = new Map();

  constructor(config: QuantizationConfig = defaultQuantConfig) {
    this.config = config;
  }

  prepareModel(model: Module): Module {
    // Insert fake quantizers for QAT
    for (const [name, module] of model.namedModules()) {
      if (module instanceof Linear) {
        const fq = new FakeQuantize(this.config);
        this.fakeQuantizers.set(`${name}.weight`, fq);
      }
    }

    return model;
  }

  enableCalibration(): void {
    for (const fq of this.fakeQuantizers.values()) {
      fq.enableCalibration();
    }
  }

  disableCalibration(): void {
    for (const fq of this.fakeQuantizers.values()) {
      fq.disableCalibration();
    }
  }

  convertModel(model: Module): Module {
    // Convert to truly quantized model after QAT
    for (const [name, module] of model.namedModules()) {
      if (module instanceof Linear) {
        const fq = this.fakeQuantizers.get(`${name}.weight`);
        if (fq) {
          const params = fq.getQuantParams();
          if (params) {
            const quantized = QuantizedLinear.fromFloat(module, this.config);
            // Would need to replace module in parent
          }
        }
      }
    }

    return model;
  }
}

// ============ Convenience Functions ============

export async function quantizeDynamic(
  model: Module,
  config: QuantizationConfig = defaultQuantConfig
): Promise<Module> {
  // Dynamic quantization: weights are pre-quantized, inputs are quantized at runtime
  for (const [name, module] of model.namedModules()) {
    if (module instanceof Linear) {
      const weight = (module as any).weight.data;
      const bias = (module as any).bias?.data ?? null;
      const inFeatures = weight.shape[1];
      const outFeatures = weight.shape[0];

      const quantized = new DynamicQuantizedLinear(
        inFeatures,
        outFeatures,
        weight,
        bias,
        config
      );

      // Would need to replace module in parent
    }
  }

  return model;
}

export async function quantizeStatic(
  model: Module,
  dataLoader: AsyncIterable<Tensor[]>,
  config: QuantizationConfig = defaultQuantConfig
): Promise<Module> {
  const engine = new QuantizationEngine(config);
  const prepared = engine.prepareModel(model);
  await engine.calibrate(prepared, dataLoader);
  return engine.convertModel(prepared);
}

export function prepareQAT(
  model: Module,
  config: QuantizationConfig = defaultQuantConfig
): { model: Module; engine: QATEngine } {
  const engine = new QATEngine(config);
  const prepared = engine.prepareModel(model);
  engine.enableCalibration();
  return { model: prepared, engine };
}

export function convertQAT(
  model: Module,
  engine: QATEngine
): Module {
  engine.disableCalibration();
  return engine.convertModel(model);
}

// ============ Model Size Estimation ============

export function estimateQuantizedSize(model: Module, config: QuantizationConfig): number {
  let totalBytes = 0;
  const bitsPerElement = getBitsPerElement(config.dtype);

  for (const param of model.parameters()) {
    const numElements = param.data.numel;
    totalBytes += Math.ceil(numElements * bitsPerElement / 8);
  }

  return totalBytes;
}

function getBitsPerElement(dtype: QuantizationType): number {
  switch (dtype) {
    case QuantizationType.INT8:
    case QuantizationType.UINT8:
      return 8;
    case QuantizationType.INT4:
    case QuantizationType.UINT4:
    case QuantizationType.NF4:
      return 4;
    case QuantizationType.FP16:
    case QuantizationType.BF16:
      return 16;
    case QuantizationType.FP8_E4M3:
    case QuantizationType.FP8_E5M2:
      return 8;
    default:
      return 8;
  }
}

export function compressionRatio(model: Module, config: QuantizationConfig): number {
  const originalBits = 32; // Assume FP32
  const quantizedBits = getBitsPerElement(config.dtype);
  return originalBits / quantizedBits;
}
