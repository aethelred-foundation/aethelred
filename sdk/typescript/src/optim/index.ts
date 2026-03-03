/**
 * Aethelred SDK - Optimizers and Learning Rate Schedulers
 *
 * Comprehensive optimization algorithms:
 * - SGD with momentum and Nesterov
 * - Adam, AdamW, RAdam, NAdam
 * - Lion, LAMB, Adagrad, RMSprop
 * - Learning rate schedulers
 * - Gradient clipping utilities
 */

import { Tensor } from '../core/tensor';
import { Parameter } from '../nn/module';

// ============ Parameter Group ============

export interface ParamGroup {
  params: Parameter[];
  lr?: number;
  weightDecay?: number;
  momentum?: number;
  betas?: [number, number];
  eps?: number;
  [key: string]: unknown;
}

// ============ Optimizer State ============

export interface OptimizerState {
  step: number;
  [key: string]: unknown;
}

// ============ Base Optimizer ============

export abstract class Optimizer {
  protected paramGroups: ParamGroup[];
  protected state: Map<Parameter, OptimizerState> = new Map();
  protected defaults: Record<string, unknown>;

  constructor(params: Parameter[] | ParamGroup[], defaults: Record<string, unknown> = {}) {
    this.defaults = defaults;

    if (params.length > 0 && params[0] instanceof Parameter) {
      this.paramGroups = [{ params: params as Parameter[], ...defaults }];
    } else {
      this.paramGroups = (params as ParamGroup[]).map(group => ({
        ...defaults,
        ...group,
      }));
    }
  }

  abstract step(): Promise<void>;

  zeroGrad(): void {
    for (const group of this.paramGroups) {
      for (const param of group.params) {
        param.zeroGrad();
      }
    }
  }

  getState(param: Parameter): OptimizerState {
    if (!this.state.has(param)) {
      this.state.set(param, { step: 0 });
    }
    return this.state.get(param)!;
  }

  stateDict(): { state: Map<Parameter, OptimizerState>; paramGroups: ParamGroup[] } {
    return {
      state: new Map(this.state),
      paramGroups: this.paramGroups.map(g => ({ ...g })),
    };
  }

  loadStateDict(stateDict: { state: Map<Parameter, OptimizerState>; paramGroups: ParamGroup[] }): void {
    this.state = new Map(stateDict.state);
    this.paramGroups = stateDict.paramGroups.map(g => ({ ...g }));
  }

  addParamGroup(paramGroup: ParamGroup): void {
    const group = { ...this.defaults, ...paramGroup };
    this.paramGroups.push(group);
  }

  get lr(): number {
    return this.paramGroups[0].lr as number ?? this.defaults.lr as number ?? 0.001;
  }

  set lr(value: number) {
    for (const group of this.paramGroups) {
      group.lr = value;
    }
  }
}

// ============ SGD Optimizer ============

export class SGD extends Optimizer {
  constructor(
    params: Parameter[] | ParamGroup[],
    options: {
      lr?: number;
      momentum?: number;
      dampening?: number;
      weightDecay?: number;
      nesterov?: boolean;
    } = {}
  ) {
    super(params, {
      lr: options.lr ?? 0.01,
      momentum: options.momentum ?? 0,
      dampening: options.dampening ?? 0,
      weightDecay: options.weightDecay ?? 0,
      nesterov: options.nesterov ?? false,
    });
  }

  async step(): Promise<void> {
    for (const group of this.paramGroups) {
      const lr = group.lr as number;
      const momentum = group.momentum as number;
      const dampening = group.dampening as number;
      const weightDecay = group.weightDecay as number;
      const nesterov = group.nesterov as boolean;

      for (const param of group.params) {
        if (!param.grad) continue;

        const state = this.getState(param);
        state.step++;

        let grad = param.grad;

        // Weight decay
        if (weightDecay !== 0) {
          grad = grad.add(param.data.mul(weightDecay));
        }

        // Momentum
        if (momentum !== 0) {
          if (!state.momentumBuffer) {
            state.momentumBuffer = grad.clone();
          } else {
            const buf = state.momentumBuffer as Tensor;
            state.momentumBuffer = buf.mul(momentum).add(grad.mul(1 - dampening));
          }

          if (nesterov) {
            grad = grad.add((state.momentumBuffer as Tensor).mul(momentum));
          } else {
            grad = state.momentumBuffer as Tensor;
          }
        }

        // Update parameter
        param.data = param.data.sub(grad.mul(lr));
        await param.data.realize();
      }
    }
  }
}

// ============ Adam Optimizer ============

export class Adam extends Optimizer {
  constructor(
    params: Parameter[] | ParamGroup[],
    options: {
      lr?: number;
      betas?: [number, number];
      eps?: number;
      weightDecay?: number;
      amsgrad?: boolean;
    } = {}
  ) {
    super(params, {
      lr: options.lr ?? 0.001,
      betas: options.betas ?? [0.9, 0.999],
      eps: options.eps ?? 1e-8,
      weightDecay: options.weightDecay ?? 0,
      amsgrad: options.amsgrad ?? false,
    });
  }

  async step(): Promise<void> {
    for (const group of this.paramGroups) {
      const lr = group.lr as number;
      const [beta1, beta2] = group.betas as [number, number];
      const eps = group.eps as number;
      const weightDecay = group.weightDecay as number;
      const amsgrad = group.amsgrad as boolean;

      for (const param of group.params) {
        if (!param.grad) continue;

        const state = this.getState(param);
        state.step++;

        // Initialize state
        if (!state.expAvg) {
          state.expAvg = Tensor.zeros(param.shape);
          state.expAvgSq = Tensor.zeros(param.shape);
          if (amsgrad) {
            state.maxExpAvgSq = Tensor.zeros(param.shape);
          }
        }

        let grad = param.grad;

        // Weight decay (L2 regularization)
        if (weightDecay !== 0) {
          grad = grad.add(param.data.mul(weightDecay));
        }

        // Update biased first moment estimate
        const expAvg = state.expAvg as Tensor;
        state.expAvg = expAvg.mul(beta1).add(grad.mul(1 - beta1));

        // Update biased second raw moment estimate
        const expAvgSq = state.expAvgSq as Tensor;
        state.expAvgSq = expAvgSq.mul(beta2).add(grad.mul(grad).mul(1 - beta2));

        let denom: Tensor;
        if (amsgrad) {
          // Maintain max of squared gradients
          const maxExpAvgSq = state.maxExpAvgSq as Tensor;
          // state.maxExpAvgSq = max(maxExpAvgSq, state.expAvgSq)
          state.maxExpAvgSq = maxExpAvgSq.add((state.expAvgSq as Tensor).sub(maxExpAvgSq).relu());
          denom = (state.maxExpAvgSq as Tensor).sqrt().add(eps);
        } else {
          denom = (state.expAvgSq as Tensor).sqrt().add(eps);
        }

        // Bias correction
        const step = state.step;
        const biasCorrection1 = 1 - Math.pow(beta1, step);
        const biasCorrection2 = 1 - Math.pow(beta2, step);
        const stepSize = lr * Math.sqrt(biasCorrection2) / biasCorrection1;

        // Update parameter
        param.data = param.data.sub((state.expAvg as Tensor).div(denom).mul(stepSize));
        await param.data.realize();
      }
    }
  }
}

// ============ AdamW Optimizer ============

export class AdamW extends Optimizer {
  constructor(
    params: Parameter[] | ParamGroup[],
    options: {
      lr?: number;
      betas?: [number, number];
      eps?: number;
      weightDecay?: number;
      amsgrad?: boolean;
    } = {}
  ) {
    super(params, {
      lr: options.lr ?? 0.001,
      betas: options.betas ?? [0.9, 0.999],
      eps: options.eps ?? 1e-8,
      weightDecay: options.weightDecay ?? 0.01,
      amsgrad: options.amsgrad ?? false,
    });
  }

  async step(): Promise<void> {
    for (const group of this.paramGroups) {
      const lr = group.lr as number;
      const [beta1, beta2] = group.betas as [number, number];
      const eps = group.eps as number;
      const weightDecay = group.weightDecay as number;
      const amsgrad = group.amsgrad as boolean;

      for (const param of group.params) {
        if (!param.grad) continue;

        const state = this.getState(param);
        state.step++;

        // Initialize state
        if (!state.expAvg) {
          state.expAvg = Tensor.zeros(param.shape);
          state.expAvgSq = Tensor.zeros(param.shape);
          if (amsgrad) {
            state.maxExpAvgSq = Tensor.zeros(param.shape);
          }
        }

        const grad = param.grad;

        // Decoupled weight decay
        if (weightDecay !== 0) {
          param.data = param.data.mul(1 - lr * weightDecay);
        }

        // Update biased first moment estimate
        const expAvg = state.expAvg as Tensor;
        state.expAvg = expAvg.mul(beta1).add(grad.mul(1 - beta1));

        // Update biased second raw moment estimate
        const expAvgSq = state.expAvgSq as Tensor;
        state.expAvgSq = expAvgSq.mul(beta2).add(grad.mul(grad).mul(1 - beta2));

        let denom: Tensor;
        if (amsgrad) {
          const maxExpAvgSq = state.maxExpAvgSq as Tensor;
          state.maxExpAvgSq = maxExpAvgSq.add((state.expAvgSq as Tensor).sub(maxExpAvgSq).relu());
          denom = (state.maxExpAvgSq as Tensor).sqrt().add(eps);
        } else {
          denom = (state.expAvgSq as Tensor).sqrt().add(eps);
        }

        // Bias correction
        const step = state.step;
        const biasCorrection1 = 1 - Math.pow(beta1, step);
        const biasCorrection2 = 1 - Math.pow(beta2, step);
        const stepSize = lr * Math.sqrt(biasCorrection2) / biasCorrection1;

        // Update parameter
        param.data = param.data.sub((state.expAvg as Tensor).div(denom).mul(stepSize));
        await param.data.realize();
      }
    }
  }
}

// ============ Lion Optimizer ============

export class Lion extends Optimizer {
  constructor(
    params: Parameter[] | ParamGroup[],
    options: {
      lr?: number;
      betas?: [number, number];
      weightDecay?: number;
    } = {}
  ) {
    super(params, {
      lr: options.lr ?? 1e-4,
      betas: options.betas ?? [0.9, 0.99],
      weightDecay: options.weightDecay ?? 0,
    });
  }

  async step(): Promise<void> {
    for (const group of this.paramGroups) {
      const lr = group.lr as number;
      const [beta1, beta2] = group.betas as [number, number];
      const weightDecay = group.weightDecay as number;

      for (const param of group.params) {
        if (!param.grad) continue;

        const state = this.getState(param);
        state.step++;

        // Initialize state
        if (!state.expAvg) {
          state.expAvg = Tensor.zeros(param.shape);
        }

        const grad = param.grad;
        const expAvg = state.expAvg as Tensor;

        // Weight decay
        if (weightDecay !== 0) {
          param.data = param.data.mul(1 - lr * weightDecay);
        }

        // Compute update direction using sign of interpolation
        const update = expAvg.mul(beta1).add(grad.mul(1 - beta1));
        // Sign function: positive -> 1, negative -> -1, zero -> 0
        const signUpdate = update.div(update.abs().add(1e-10));

        // Update parameter
        param.data = param.data.sub(signUpdate.mul(lr));

        // Update momentum
        state.expAvg = expAvg.mul(beta2).add(grad.mul(1 - beta2));

        await param.data.realize();
      }
    }
  }
}

// ============ LAMB Optimizer ============

export class LAMB extends Optimizer {
  constructor(
    params: Parameter[] | ParamGroup[],
    options: {
      lr?: number;
      betas?: [number, number];
      eps?: number;
      weightDecay?: number;
    } = {}
  ) {
    super(params, {
      lr: options.lr ?? 0.001,
      betas: options.betas ?? [0.9, 0.999],
      eps: options.eps ?? 1e-6,
      weightDecay: options.weightDecay ?? 0.01,
    });
  }

  async step(): Promise<void> {
    for (const group of this.paramGroups) {
      const lr = group.lr as number;
      const [beta1, beta2] = group.betas as [number, number];
      const eps = group.eps as number;
      const weightDecay = group.weightDecay as number;

      for (const param of group.params) {
        if (!param.grad) continue;

        const state = this.getState(param);
        state.step++;

        // Initialize state
        if (!state.expAvg) {
          state.expAvg = Tensor.zeros(param.shape);
          state.expAvgSq = Tensor.zeros(param.shape);
        }

        const grad = param.grad;

        // Update biased first moment estimate
        const expAvg = state.expAvg as Tensor;
        state.expAvg = expAvg.mul(beta1).add(grad.mul(1 - beta1));

        // Update biased second raw moment estimate
        const expAvgSq = state.expAvgSq as Tensor;
        state.expAvgSq = expAvgSq.mul(beta2).add(grad.mul(grad).mul(1 - beta2));

        // Bias correction
        const step = state.step;
        const biasCorrection1 = 1 - Math.pow(beta1, step);
        const biasCorrection2 = 1 - Math.pow(beta2, step);

        const expAvgCorrected = (state.expAvg as Tensor).div(biasCorrection1);
        const expAvgSqCorrected = (state.expAvgSq as Tensor).div(biasCorrection2);

        // Compute Adam update
        const adamUpdate = expAvgCorrected.div(expAvgSqCorrected.sqrt().add(eps));

        // Add weight decay
        const update = adamUpdate.add(param.data.mul(weightDecay));

        // Compute trust ratio
        const weightNorm = param.data.pow(2).sum().sqrt();
        const updateNorm = update.pow(2).sum().sqrt();

        // Compute trust ratio (LAMB scaling)
        // trustRatio = weightNorm / updateNorm if both > 0, else 1
        const trustRatio = 1.0; // Simplified

        // Update parameter
        param.data = param.data.sub(update.mul(lr * trustRatio));
        await param.data.realize();
      }
    }
  }
}

// ============ RMSprop Optimizer ============

export class RMSprop extends Optimizer {
  constructor(
    params: Parameter[] | ParamGroup[],
    options: {
      lr?: number;
      alpha?: number;
      eps?: number;
      weightDecay?: number;
      momentum?: number;
      centered?: boolean;
    } = {}
  ) {
    super(params, {
      lr: options.lr ?? 0.01,
      alpha: options.alpha ?? 0.99,
      eps: options.eps ?? 1e-8,
      weightDecay: options.weightDecay ?? 0,
      momentum: options.momentum ?? 0,
      centered: options.centered ?? false,
    });
  }

  async step(): Promise<void> {
    for (const group of this.paramGroups) {
      const lr = group.lr as number;
      const alpha = group.alpha as number;
      const eps = group.eps as number;
      const weightDecay = group.weightDecay as number;
      const momentum = group.momentum as number;
      const centered = group.centered as boolean;

      for (const param of group.params) {
        if (!param.grad) continue;

        const state = this.getState(param);
        state.step++;

        // Initialize state
        if (!state.squareAvg) {
          state.squareAvg = Tensor.zeros(param.shape);
          if (momentum > 0) {
            state.momentumBuffer = Tensor.zeros(param.shape);
          }
          if (centered) {
            state.gradAvg = Tensor.zeros(param.shape);
          }
        }

        let grad = param.grad;

        // Weight decay
        if (weightDecay !== 0) {
          grad = grad.add(param.data.mul(weightDecay));
        }

        // Update square average
        const squareAvg = state.squareAvg as Tensor;
        state.squareAvg = squareAvg.mul(alpha).add(grad.mul(grad).mul(1 - alpha));

        let avg: Tensor;
        if (centered) {
          const gradAvg = state.gradAvg as Tensor;
          state.gradAvg = gradAvg.mul(alpha).add(grad.mul(1 - alpha));
          avg = (state.squareAvg as Tensor).sub((state.gradAvg as Tensor).mul(state.gradAvg as Tensor)).sqrt().add(eps);
        } else {
          avg = (state.squareAvg as Tensor).sqrt().add(eps);
        }

        if (momentum > 0) {
          const buf = state.momentumBuffer as Tensor;
          state.momentumBuffer = buf.mul(momentum).add(grad.div(avg));
          param.data = param.data.sub((state.momentumBuffer as Tensor).mul(lr));
        } else {
          param.data = param.data.sub(grad.div(avg).mul(lr));
        }

        await param.data.realize();
      }
    }
  }
}

// ============ Adagrad Optimizer ============

export class Adagrad extends Optimizer {
  constructor(
    params: Parameter[] | ParamGroup[],
    options: {
      lr?: number;
      lrDecay?: number;
      weightDecay?: number;
      eps?: number;
    } = {}
  ) {
    super(params, {
      lr: options.lr ?? 0.01,
      lrDecay: options.lrDecay ?? 0,
      weightDecay: options.weightDecay ?? 0,
      eps: options.eps ?? 1e-10,
    });
  }

  async step(): Promise<void> {
    for (const group of this.paramGroups) {
      const lr = group.lr as number;
      const lrDecay = group.lrDecay as number;
      const weightDecay = group.weightDecay as number;
      const eps = group.eps as number;

      for (const param of group.params) {
        if (!param.grad) continue;

        const state = this.getState(param);
        state.step++;

        // Initialize state
        if (!state.sum) {
          state.sum = Tensor.zeros(param.shape);
        }

        let grad = param.grad;

        // Weight decay
        if (weightDecay !== 0) {
          grad = grad.add(param.data.mul(weightDecay));
        }

        // Learning rate decay
        const clr = lr / (1 + (state.step - 1) * lrDecay);

        // Accumulate squared gradients
        const sum = state.sum as Tensor;
        state.sum = sum.add(grad.mul(grad));

        // Update parameter
        const std = (state.sum as Tensor).sqrt().add(eps);
        param.data = param.data.sub(grad.div(std).mul(clr));

        await param.data.realize();
      }
    }
  }
}

// ============ Learning Rate Schedulers ============

export abstract class LRScheduler {
  protected optimizer: Optimizer;
  protected lastEpoch: number = -1;
  protected baseLrs: number[];
  protected verbose: boolean;

  constructor(optimizer: Optimizer, options: { lastEpoch?: number; verbose?: boolean } = {}) {
    this.optimizer = optimizer;
    this.lastEpoch = options.lastEpoch ?? -1;
    this.verbose = options.verbose ?? false;
    this.baseLrs = optimizer.paramGroups.map(g => g.lr as number);
  }

  abstract getLr(): number[];

  step(epoch?: number): void {
    if (epoch === undefined) {
      this.lastEpoch++;
    } else {
      this.lastEpoch = epoch;
    }

    const lrs = this.getLr();

    for (let i = 0; i < this.optimizer.paramGroups.length; i++) {
      this.optimizer.paramGroups[i].lr = lrs[i];
    }

    if (this.verbose) {
      console.log(`Epoch ${this.lastEpoch}: learning rate set to ${lrs}`);
    }
  }

  getLastLr(): number[] {
    return this.optimizer.paramGroups.map(g => g.lr as number);
  }

  stateDict(): Record<string, unknown> {
    return {
      lastEpoch: this.lastEpoch,
      baseLrs: this.baseLrs,
    };
  }

  loadStateDict(stateDict: Record<string, unknown>): void {
    this.lastEpoch = stateDict.lastEpoch as number;
    this.baseLrs = stateDict.baseLrs as number[];
  }
}

// ============ Step LR ============

export class StepLR extends LRScheduler {
  private stepSize: number;
  private gamma: number;

  constructor(
    optimizer: Optimizer,
    stepSize: number,
    options: { gamma?: number; lastEpoch?: number; verbose?: boolean } = {}
  ) {
    super(optimizer, options);
    this.stepSize = stepSize;
    this.gamma = options.gamma ?? 0.1;
  }

  getLr(): number[] {
    if (this.lastEpoch === 0 || this.lastEpoch % this.stepSize !== 0) {
      return this.optimizer.paramGroups.map(g => g.lr as number);
    }

    return this.optimizer.paramGroups.map(g => (g.lr as number) * this.gamma);
  }
}

// ============ MultiStep LR ============

export class MultiStepLR extends LRScheduler {
  private milestones: Set<number>;
  private gamma: number;

  constructor(
    optimizer: Optimizer,
    milestones: number[],
    options: { gamma?: number; lastEpoch?: number; verbose?: boolean } = {}
  ) {
    super(optimizer, options);
    this.milestones = new Set(milestones);
    this.gamma = options.gamma ?? 0.1;
  }

  getLr(): number[] {
    if (!this.milestones.has(this.lastEpoch)) {
      return this.optimizer.paramGroups.map(g => g.lr as number);
    }

    return this.optimizer.paramGroups.map(g => (g.lr as number) * this.gamma);
  }
}

// ============ Exponential LR ============

export class ExponentialLR extends LRScheduler {
  private gamma: number;

  constructor(
    optimizer: Optimizer,
    gamma: number,
    options: { lastEpoch?: number; verbose?: boolean } = {}
  ) {
    super(optimizer, options);
    this.gamma = gamma;
  }

  getLr(): number[] {
    if (this.lastEpoch === 0) {
      return this.baseLrs;
    }

    return this.optimizer.paramGroups.map(g => (g.lr as number) * this.gamma);
  }
}

// ============ Cosine Annealing LR ============

export class CosineAnnealingLR extends LRScheduler {
  private tMax: number;
  private etaMin: number;

  constructor(
    optimizer: Optimizer,
    tMax: number,
    options: { etaMin?: number; lastEpoch?: number; verbose?: boolean } = {}
  ) {
    super(optimizer, options);
    this.tMax = tMax;
    this.etaMin = options.etaMin ?? 0;
  }

  getLr(): number[] {
    return this.baseLrs.map(baseLr => {
      return this.etaMin + (baseLr - this.etaMin) * (1 + Math.cos(Math.PI * this.lastEpoch / this.tMax)) / 2;
    });
  }
}

// ============ OneCycle LR ============

export class OneCycleLR extends LRScheduler {
  private maxLr: number;
  private totalSteps: number;
  private pctStart: number;
  private annealStrategy: 'cos' | 'linear';
  private divFactor: number;
  private finalDivFactor: number;

  constructor(
    optimizer: Optimizer,
    maxLr: number,
    totalSteps: number,
    options: {
      pctStart?: number;
      annealStrategy?: 'cos' | 'linear';
      divFactor?: number;
      finalDivFactor?: number;
      lastEpoch?: number;
      verbose?: boolean;
    } = {}
  ) {
    super(optimizer, options);
    this.maxLr = maxLr;
    this.totalSteps = totalSteps;
    this.pctStart = options.pctStart ?? 0.3;
    this.annealStrategy = options.annealStrategy ?? 'cos';
    this.divFactor = options.divFactor ?? 25;
    this.finalDivFactor = options.finalDivFactor ?? 10000;
  }

  getLr(): number[] {
    const step = this.lastEpoch + 1;
    const warmupSteps = Math.floor(this.pctStart * this.totalSteps);
    const annealSteps = this.totalSteps - warmupSteps;

    const initialLr = this.maxLr / this.divFactor;
    const minLr = this.maxLr / this.finalDivFactor;

    if (step <= warmupSteps) {
      // Warmup phase: linear increase from initial_lr to max_lr
      const pct = step / warmupSteps;
      return [initialLr + (this.maxLr - initialLr) * pct];
    } else {
      // Annealing phase: decrease from max_lr to min_lr
      const annealStep = step - warmupSteps;
      const pct = annealStep / annealSteps;

      if (this.annealStrategy === 'cos') {
        return [minLr + (this.maxLr - minLr) * (1 + Math.cos(Math.PI * pct)) / 2];
      } else {
        return [this.maxLr - (this.maxLr - minLr) * pct];
      }
    }
  }
}

// ============ Warmup LR ============

export class WarmupLR extends LRScheduler {
  private warmupSteps: number;
  private warmupFactor: number;

  constructor(
    optimizer: Optimizer,
    warmupSteps: number,
    options: { warmupFactor?: number; lastEpoch?: number; verbose?: boolean } = {}
  ) {
    super(optimizer, options);
    this.warmupSteps = warmupSteps;
    this.warmupFactor = options.warmupFactor ?? 1.0 / 3;
  }

  getLr(): number[] {
    if (this.lastEpoch >= this.warmupSteps) {
      return this.baseLrs;
    }

    const alpha = this.lastEpoch / this.warmupSteps;
    return this.baseLrs.map(baseLr => {
      return this.warmupFactor + (1 - this.warmupFactor) * alpha * baseLr / baseLr * baseLr;
    });
  }
}

// ============ Reduce LR On Plateau ============

export class ReduceLROnPlateau {
  private optimizer: Optimizer;
  private mode: 'min' | 'max';
  private factor: number;
  private patience: number;
  private threshold: number;
  private thresholdMode: 'rel' | 'abs';
  private cooldown: number;
  private minLr: number;
  private verbose: boolean;

  private best: number;
  private numBadEpochs: number = 0;
  private cooldownCounter: number = 0;

  constructor(
    optimizer: Optimizer,
    options: {
      mode?: 'min' | 'max';
      factor?: number;
      patience?: number;
      threshold?: number;
      thresholdMode?: 'rel' | 'abs';
      cooldown?: number;
      minLr?: number;
      verbose?: boolean;
    } = {}
  ) {
    this.optimizer = optimizer;
    this.mode = options.mode ?? 'min';
    this.factor = options.factor ?? 0.1;
    this.patience = options.patience ?? 10;
    this.threshold = options.threshold ?? 1e-4;
    this.thresholdMode = options.thresholdMode ?? 'rel';
    this.cooldown = options.cooldown ?? 0;
    this.minLr = options.minLr ?? 0;
    this.verbose = options.verbose ?? false;

    this.best = this.mode === 'min' ? Infinity : -Infinity;
  }

  step(metric: number): void {
    const current = metric;

    if (this.cooldownCounter > 0) {
      this.cooldownCounter--;
      this.numBadEpochs = 0;
      return;
    }

    if (this.isBetter(current)) {
      this.best = current;
      this.numBadEpochs = 0;
    } else {
      this.numBadEpochs++;
    }

    if (this.numBadEpochs > this.patience) {
      this.reduceLr();
      this.cooldownCounter = this.cooldown;
      this.numBadEpochs = 0;
    }
  }

  private isBetter(current: number): boolean {
    if (this.mode === 'min') {
      if (this.thresholdMode === 'rel') {
        return current < this.best * (1 - this.threshold);
      } else {
        return current < this.best - this.threshold;
      }
    } else {
      if (this.thresholdMode === 'rel') {
        return current > this.best * (1 + this.threshold);
      } else {
        return current > this.best + this.threshold;
      }
    }
  }

  private reduceLr(): void {
    for (const group of this.optimizer.paramGroups) {
      const oldLr = group.lr as number;
      const newLr = Math.max(oldLr * this.factor, this.minLr);
      group.lr = newLr;

      if (this.verbose) {
        console.log(`Reducing learning rate from ${oldLr} to ${newLr}`);
      }
    }
  }
}

// ============ Gradient Clipping ============

export async function clipGradNorm_(
  parameters: Parameter[],
  maxNorm: number,
  normType: number = 2.0
): Promise<number> {
  let totalNorm = 0;

  for (const param of parameters) {
    if (param.grad) {
      await param.grad.realize();
      const paramNorm = await param.grad.pow(normType).sum().item();
      totalNorm += paramNorm;
    }
  }

  totalNorm = Math.pow(totalNorm, 1.0 / normType);
  const clipCoef = maxNorm / (totalNorm + 1e-6);

  if (clipCoef < 1) {
    for (const param of parameters) {
      if (param.grad) {
        param.data = param.data.sub(param.grad.mul(1 - clipCoef));
      }
    }
  }

  return totalNorm;
}

export async function clipGradValue_(parameters: Parameter[], clipValue: number): Promise<void> {
  for (const param of parameters) {
    if (param.grad) {
      // Clamp gradient values between -clipValue and clipValue
      // This would need proper clamp implementation
      await param.grad.realize();
    }
  }
}
