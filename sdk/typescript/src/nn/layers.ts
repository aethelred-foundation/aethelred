/**
 * Aethelred SDK - Neural Network Layers
 *
 * Comprehensive layer implementations:
 * - Linear layers
 * - Normalization layers
 * - Activation functions
 * - Dropout layers
 * - Embedding layers
 * - Attention mechanisms
 * - Transformer components
 */

import { Tensor, DType } from '../core/tensor';
import { Module, Parameter, Buffer } from './module';

// ============ Initialization Utilities ============

function kaiming_uniform_(shape: number[], a: number = 0, mode: 'fan_in' | 'fan_out' = 'fan_in'): Tensor {
  const fan = mode === 'fan_in' ? shape[shape.length - 1] : shape[0];
  const gain = Math.sqrt(2.0 / (1 + a * a));
  const std = gain / Math.sqrt(fan);
  const bound = Math.sqrt(3.0) * std;

  const size = shape.reduce((a, b) => a * b, 1);
  const data = Array.from({ length: size }, () => (Math.random() * 2 - 1) * bound);

  return new Tensor(data, { shape });
}

function xavier_uniform_(shape: number[]): Tensor {
  const fanIn = shape[shape.length - 1];
  const fanOut = shape[0];
  const std = Math.sqrt(2.0 / (fanIn + fanOut));
  const bound = Math.sqrt(3.0) * std;

  const size = shape.reduce((a, b) => a * b, 1);
  const data = Array.from({ length: size }, () => (Math.random() * 2 - 1) * bound);

  return new Tensor(data, { shape });
}

// ============ Linear Layer ============

export class Linear extends Module {
  private inFeatures: number;
  private outFeatures: number;
  private weight: Parameter;
  private bias: Parameter | null;

  constructor(inFeatures: number, outFeatures: number, options: { bias?: boolean } = {}) {
    super();
    this.inFeatures = inFeatures;
    this.outFeatures = outFeatures;

    this.weight = new Parameter(kaiming_uniform_([outFeatures, inFeatures]));
    this.registerParameter('weight', this.weight);

    if (options.bias !== false) {
      const bound = 1 / Math.sqrt(inFeatures);
      const biasData = Array.from({ length: outFeatures }, () => (Math.random() * 2 - 1) * bound);
      this.bias = new Parameter(new Tensor(biasData));
      this.registerParameter('bias', this.bias);
    } else {
      this.bias = null;
    }
  }

  forward(input: Tensor): Tensor {
    // input: [..., inFeatures]
    // weight: [outFeatures, inFeatures]
    // output: [..., outFeatures]

    let output = input.matmul(this.weight.data.t());

    if (this.bias) {
      output = output.add(this.bias.data);
    }

    return output;
  }

  extraRepr(): string {
    return `in_features=${this.inFeatures}, out_features=${this.outFeatures}, bias=${this.bias !== null}`;
  }
}

// ============ Embedding Layer ============

export class Embedding extends Module {
  private numEmbeddings: number;
  private embeddingDim: number;
  private paddingIdx: number | null;
  private weight: Parameter;

  constructor(
    numEmbeddings: number,
    embeddingDim: number,
    options: { paddingIdx?: number } = {}
  ) {
    super();
    this.numEmbeddings = numEmbeddings;
    this.embeddingDim = embeddingDim;
    this.paddingIdx = options.paddingIdx ?? null;

    // Initialize with normal distribution
    const data = Tensor.randn([numEmbeddings, embeddingDim]);
    this.weight = new Parameter(data);
    this.registerParameter('weight', this.weight);

    if (this.paddingIdx !== null) {
      // Zero out padding vector
      // Note: This would need proper implementation with indexing
    }
  }

  forward(input: Tensor): Tensor {
    // input: [..., seq_len] (indices)
    // output: [..., seq_len, embeddingDim]

    // For now, we'll create a lazy operation
    // Full implementation would index into weight matrix
    const outputShape = [...input.shape, this.embeddingDim];

    // This is a placeholder - real implementation needs gather operation
    return Tensor.zeros(outputShape);
  }

  extraRepr(): string {
    return `num_embeddings=${this.numEmbeddings}, embedding_dim=${this.embeddingDim}` +
           (this.paddingIdx !== null ? `, padding_idx=${this.paddingIdx}` : '');
  }
}

// ============ Normalization Layers ============

export class LayerNorm extends Module {
  private normalizedShape: number[];
  private eps: number;
  private elementwiseAffine: boolean;
  private weight: Parameter | null = null;
  private bias: Parameter | null = null;

  constructor(
    normalizedShape: number | number[],
    options: { eps?: number; elementwiseAffine?: boolean } = {}
  ) {
    super();
    this.normalizedShape = Array.isArray(normalizedShape) ? normalizedShape : [normalizedShape];
    this.eps = options.eps ?? 1e-5;
    this.elementwiseAffine = options.elementwiseAffine ?? true;

    if (this.elementwiseAffine) {
      this.weight = new Parameter(Tensor.ones(this.normalizedShape));
      this.bias = new Parameter(Tensor.zeros(this.normalizedShape));
      this.registerParameter('weight', this.weight);
      this.registerParameter('bias', this.bias);
    }
  }

  forward(input: Tensor): Tensor {
    // Compute mean and variance over normalized dimensions
    const mean = input.mean(-1, true);
    const variance = input.var(-1, true, 0);

    // Normalize
    let normalized = input.sub(mean).div(variance.add(this.eps).sqrt());

    // Apply affine transformation
    if (this.elementwiseAffine && this.weight && this.bias) {
      normalized = normalized.mul(this.weight.data).add(this.bias.data);
    }

    return normalized;
  }

  extraRepr(): string {
    return `normalized_shape=${this.normalizedShape}, eps=${this.eps}, elementwise_affine=${this.elementwiseAffine}`;
  }
}

export class BatchNorm1d extends Module {
  private numFeatures: number;
  private eps: number;
  private momentum: number;
  private affine: boolean;
  private trackRunningStats: boolean;

  private weight: Parameter | null = null;
  private bias: Parameter | null = null;
  private runningMean: Buffer | null = null;
  private runningVar: Buffer | null = null;
  private numBatchesTracked: Buffer | null = null;

  constructor(
    numFeatures: number,
    options: { eps?: number; momentum?: number; affine?: boolean; trackRunningStats?: boolean } = {}
  ) {
    super();
    this.numFeatures = numFeatures;
    this.eps = options.eps ?? 1e-5;
    this.momentum = options.momentum ?? 0.1;
    this.affine = options.affine ?? true;
    this.trackRunningStats = options.trackRunningStats ?? true;

    if (this.affine) {
      this.weight = new Parameter(Tensor.ones([numFeatures]));
      this.bias = new Parameter(Tensor.zeros([numFeatures]));
      this.registerParameter('weight', this.weight);
      this.registerParameter('bias', this.bias);
    }

    if (this.trackRunningStats) {
      this.runningMean = new Buffer(Tensor.zeros([numFeatures]));
      this.runningVar = new Buffer(Tensor.ones([numFeatures]));
      this.numBatchesTracked = new Buffer(new Tensor([0]));
      this.registerBuffer('running_mean', this.runningMean);
      this.registerBuffer('running_var', this.runningVar);
      this.registerBuffer('num_batches_tracked', this.numBatchesTracked);
    }
  }

  forward(input: Tensor): Tensor {
    let mean: Tensor;
    let variance: Tensor;

    if (this.training && this.trackRunningStats) {
      // Use batch statistics during training
      mean = input.mean(0, false);
      variance = input.var(0, false, 0);

      // Update running statistics
      // This would need proper exponential moving average update
    } else if (this.runningMean && this.runningVar) {
      // Use running statistics during evaluation
      mean = this.runningMean.data;
      variance = this.runningVar.data;
    } else {
      mean = input.mean(0, false);
      variance = input.var(0, false, 0);
    }

    // Normalize
    let normalized = input.sub(mean).div(variance.add(this.eps).sqrt());

    // Apply affine transformation
    if (this.affine && this.weight && this.bias) {
      normalized = normalized.mul(this.weight.data).add(this.bias.data);
    }

    return normalized;
  }

  extraRepr(): string {
    return `num_features=${this.numFeatures}, eps=${this.eps}, momentum=${this.momentum}, ` +
           `affine=${this.affine}, track_running_stats=${this.trackRunningStats}`;
  }
}

export class RMSNorm extends Module {
  private normalizedShape: number[];
  private eps: number;
  private weight: Parameter;

  constructor(normalizedShape: number | number[], options: { eps?: number } = {}) {
    super();
    this.normalizedShape = Array.isArray(normalizedShape) ? normalizedShape : [normalizedShape];
    this.eps = options.eps ?? 1e-6;

    this.weight = new Parameter(Tensor.ones(this.normalizedShape));
    this.registerParameter('weight', this.weight);
  }

  forward(input: Tensor): Tensor {
    // RMS = sqrt(mean(x^2))
    const rms = input.pow(2).mean(-1, true).add(this.eps).sqrt();
    return input.div(rms).mul(this.weight.data);
  }

  extraRepr(): string {
    return `normalized_shape=${this.normalizedShape}, eps=${this.eps}`;
  }
}

// ============ Activation Functions ============

export class ReLU extends Module {
  private inplace: boolean;

  constructor(options: { inplace?: boolean } = {}) {
    super();
    this.inplace = options.inplace ?? false;
  }

  forward(input: Tensor): Tensor {
    return input.relu();
  }

  extraRepr(): string {
    return this.inplace ? 'inplace=True' : '';
  }
}

export class GELU extends Module {
  private approximate: 'none' | 'tanh';

  constructor(options: { approximate?: 'none' | 'tanh' } = {}) {
    super();
    this.approximate = options.approximate ?? 'none';
  }

  forward(input: Tensor): Tensor {
    return input.gelu();
  }

  extraRepr(): string {
    return `approximate='${this.approximate}'`;
  }
}

export class SiLU extends Module {
  private inplace: boolean;

  constructor(options: { inplace?: boolean } = {}) {
    super();
    this.inplace = options.inplace ?? false;
  }

  forward(input: Tensor): Tensor {
    return input.silu();
  }
}

export class Sigmoid extends Module {
  forward(input: Tensor): Tensor {
    return input.sigmoid();
  }
}

export class Tanh extends Module {
  forward(input: Tensor): Tensor {
    return input.tanh();
  }
}

export class Softmax extends Module {
  private dim: number;

  constructor(dim: number = -1) {
    super();
    this.dim = dim;
  }

  forward(input: Tensor): Tensor {
    // Softmax = exp(x - max(x)) / sum(exp(x - max(x)))
    const maxVal = input.max(this.dim, true);
    const shifted = input.sub(maxVal);
    const expVals = shifted.exp();
    const sumExp = expVals.sum(this.dim, true);
    return expVals.div(sumExp);
  }

  extraRepr(): string {
    return `dim=${this.dim}`;
  }
}

export class LeakyReLU extends Module {
  private negativeSlope: number;
  private inplace: boolean;

  constructor(options: { negativeSlope?: number; inplace?: boolean } = {}) {
    super();
    this.negativeSlope = options.negativeSlope ?? 0.01;
    this.inplace = options.inplace ?? false;
  }

  forward(input: Tensor): Tensor {
    // LeakyReLU(x) = max(0, x) + negativeSlope * min(0, x)
    const positive = input.relu();
    const negative = input.neg().relu().neg().mul(this.negativeSlope);
    return positive.add(negative);
  }

  extraRepr(): string {
    return `negative_slope=${this.negativeSlope}`;
  }
}

export class ELU extends Module {
  private alpha: number;
  private inplace: boolean;

  constructor(options: { alpha?: number; inplace?: boolean } = {}) {
    super();
    this.alpha = options.alpha ?? 1.0;
    this.inplace = options.inplace ?? false;
  }

  forward(input: Tensor): Tensor {
    // ELU(x) = x if x > 0, else alpha * (exp(x) - 1)
    const positive = input.relu();
    const negative = input.neg().relu().neg();
    const expPart = negative.exp().sub(Tensor.ones(input.shape)).mul(this.alpha);

    // Combine: use positive where x > 0, expPart otherwise
    // This is simplified - full implementation needs conditional logic
    return positive.add(expPart);
  }

  extraRepr(): string {
    return `alpha=${this.alpha}`;
  }
}

// ============ Dropout ============

export class Dropout extends Module {
  private p: number;
  private inplace: boolean;

  constructor(p: number = 0.5, options: { inplace?: boolean } = {}) {
    super();
    this.p = p;
    this.inplace = options.inplace ?? false;
  }

  forward(input: Tensor): Tensor {
    if (!this.training || this.p === 0) {
      return input;
    }

    // Generate dropout mask
    const mask = Tensor.rand(input.shape);
    // This would need proper comparison operators
    // mask = mask > p => 1, else 0
    // output = input * mask / (1 - p)

    // Simplified: just return input scaled (placeholder)
    return input.mul(1.0 / (1.0 - this.p));
  }

  extraRepr(): string {
    return `p=${this.p}, inplace=${this.inplace}`;
  }
}

export class Dropout2d extends Dropout {
  forward(input: Tensor): Tensor {
    if (!this.training) {
      return input;
    }

    // Drop entire channels
    // For [N, C, H, W], drop at [N, C, 1, 1] level
    return super.forward(input);
  }
}

// ============ Attention Mechanisms ============

export class MultiheadAttention extends Module {
  private embedDim: number;
  private numHeads: number;
  private headDim: number;
  private dropout: number;
  private batchFirst: boolean;

  private qProj: Linear;
  private kProj: Linear;
  private vProj: Linear;
  private outProj: Linear;

  constructor(
    embedDim: number,
    numHeads: number,
    options: {
      dropout?: number;
      bias?: boolean;
      batchFirst?: boolean;
      kdim?: number;
      vdim?: number;
    } = {}
  ) {
    super();

    if (embedDim % numHeads !== 0) {
      throw new Error(`embed_dim must be divisible by num_heads`);
    }

    this.embedDim = embedDim;
    this.numHeads = numHeads;
    this.headDim = embedDim / numHeads;
    this.dropout = options.dropout ?? 0.0;
    this.batchFirst = options.batchFirst ?? true;

    const kdim = options.kdim ?? embedDim;
    const vdim = options.vdim ?? embedDim;
    const bias = options.bias ?? true;

    this.qProj = new Linear(embedDim, embedDim, { bias });
    this.kProj = new Linear(kdim, embedDim, { bias });
    this.vProj = new Linear(vdim, embedDim, { bias });
    this.outProj = new Linear(embedDim, embedDim, { bias });

    this.registerModule('q_proj', this.qProj);
    this.registerModule('k_proj', this.kProj);
    this.registerModule('v_proj', this.vProj);
    this.registerModule('out_proj', this.outProj);
  }

  forward(
    query: Tensor,
    key?: Tensor,
    value?: Tensor,
    options: {
      keyPaddingMask?: Tensor;
      needWeights?: boolean;
      attnMask?: Tensor;
    } = {}
  ): Tensor {
    key = key ?? query;
    value = value ?? query;

    // Get dimensions
    const batchSize = this.batchFirst ? query.shape[0] : query.shape[1];
    const seqLen = this.batchFirst ? query.shape[1] : query.shape[0];

    // Project Q, K, V
    let q = this.qProj.forward(query);
    let k = this.kProj.forward(key);
    let v = this.vProj.forward(value);

    // Reshape for multi-head attention
    // [batch, seq, embed] -> [batch, seq, num_heads, head_dim] -> [batch, num_heads, seq, head_dim]
    q = q.reshape([batchSize, seqLen, this.numHeads, this.headDim]).permute([0, 2, 1, 3]);
    k = k.reshape([batchSize, -1, this.numHeads, this.headDim]).permute([0, 2, 1, 3]);
    v = v.reshape([batchSize, -1, this.numHeads, this.headDim]).permute([0, 2, 1, 3]);

    // Scaled dot-product attention
    const scale = 1.0 / Math.sqrt(this.headDim);
    let attnWeights = q.matmul(k.transpose(-2, -1)).mul(scale);

    // Apply attention mask if provided
    if (options.attnMask) {
      attnWeights = attnWeights.add(options.attnMask);
    }

    // Softmax
    const softmax = new Softmax(-1);
    attnWeights = softmax.forward(attnWeights);

    // Apply dropout during training
    if (this.training && this.dropout > 0) {
      const dropoutLayer = new Dropout(this.dropout);
      attnWeights = dropoutLayer.forward(attnWeights);
    }

    // Compute attention output
    let attnOutput = attnWeights.matmul(v);

    // Reshape back: [batch, num_heads, seq, head_dim] -> [batch, seq, embed]
    attnOutput = attnOutput.permute([0, 2, 1, 3]).reshape([batchSize, seqLen, this.embedDim]);

    // Output projection
    attnOutput = this.outProj.forward(attnOutput);

    return attnOutput;
  }

  extraRepr(): string {
    return `embed_dim=${this.embedDim}, num_heads=${this.numHeads}, dropout=${this.dropout}, batch_first=${this.batchFirst}`;
  }
}

// ============ Transformer Components ============

export class TransformerEncoderLayer extends Module {
  private dModel: number;
  private nHead: number;
  private dimFeedforward: number;
  private dropout: number;

  private selfAttn: MultiheadAttention;
  private linear1: Linear;
  private linear2: Linear;
  private norm1: LayerNorm;
  private norm2: LayerNorm;
  private dropoutLayer: Dropout;
  private activation: Module;

  constructor(
    dModel: number,
    nHead: number,
    options: {
      dimFeedforward?: number;
      dropout?: number;
      activation?: 'relu' | 'gelu';
      batchFirst?: boolean;
      normFirst?: boolean;
    } = {}
  ) {
    super();

    this.dModel = dModel;
    this.nHead = nHead;
    this.dimFeedforward = options.dimFeedforward ?? 2048;
    this.dropout = options.dropout ?? 0.1;

    this.selfAttn = new MultiheadAttention(dModel, nHead, {
      dropout: this.dropout,
      batchFirst: options.batchFirst ?? true,
    });

    this.linear1 = new Linear(dModel, this.dimFeedforward);
    this.linear2 = new Linear(this.dimFeedforward, dModel);

    this.norm1 = new LayerNorm(dModel);
    this.norm2 = new LayerNorm(dModel);

    this.dropoutLayer = new Dropout(this.dropout);

    this.activation = options.activation === 'gelu' ? new GELU() : new ReLU();

    this.registerModule('self_attn', this.selfAttn);
    this.registerModule('linear1', this.linear1);
    this.registerModule('linear2', this.linear2);
    this.registerModule('norm1', this.norm1);
    this.registerModule('norm2', this.norm2);
    this.registerModule('dropout', this.dropoutLayer);
    this.registerModule('activation', this.activation);
  }

  forward(src: Tensor, options: { srcMask?: Tensor; srcKeyPaddingMask?: Tensor } = {}): Tensor {
    // Self-attention with residual
    let attnOutput = this.selfAttn.forward(src, src, src, {
      attnMask: options.srcMask,
      keyPaddingMask: options.srcKeyPaddingMask,
    });
    attnOutput = this.dropoutLayer.forward(attnOutput);
    let x = this.norm1.forward(src.add(attnOutput));

    // Feedforward with residual
    let ffOutput = this.linear1.forward(x);
    ffOutput = this.activation.forward(ffOutput);
    ffOutput = this.dropoutLayer.forward(ffOutput);
    ffOutput = this.linear2.forward(ffOutput);
    ffOutput = this.dropoutLayer.forward(ffOutput);

    x = this.norm2.forward(x.add(ffOutput));

    return x;
  }

  extraRepr(): string {
    return `d_model=${this.dModel}, nhead=${this.nHead}, dim_feedforward=${this.dimFeedforward}, dropout=${this.dropout}`;
  }
}

export class TransformerDecoderLayer extends Module {
  private dModel: number;
  private nHead: number;
  private dimFeedforward: number;
  private dropout: number;

  private selfAttn: MultiheadAttention;
  private multiheadAttn: MultiheadAttention;
  private linear1: Linear;
  private linear2: Linear;
  private norm1: LayerNorm;
  private norm2: LayerNorm;
  private norm3: LayerNorm;
  private dropoutLayer: Dropout;
  private activation: Module;

  constructor(
    dModel: number,
    nHead: number,
    options: {
      dimFeedforward?: number;
      dropout?: number;
      activation?: 'relu' | 'gelu';
      batchFirst?: boolean;
    } = {}
  ) {
    super();

    this.dModel = dModel;
    this.nHead = nHead;
    this.dimFeedforward = options.dimFeedforward ?? 2048;
    this.dropout = options.dropout ?? 0.1;

    this.selfAttn = new MultiheadAttention(dModel, nHead, {
      dropout: this.dropout,
      batchFirst: options.batchFirst ?? true,
    });

    this.multiheadAttn = new MultiheadAttention(dModel, nHead, {
      dropout: this.dropout,
      batchFirst: options.batchFirst ?? true,
    });

    this.linear1 = new Linear(dModel, this.dimFeedforward);
    this.linear2 = new Linear(this.dimFeedforward, dModel);

    this.norm1 = new LayerNorm(dModel);
    this.norm2 = new LayerNorm(dModel);
    this.norm3 = new LayerNorm(dModel);

    this.dropoutLayer = new Dropout(this.dropout);
    this.activation = options.activation === 'gelu' ? new GELU() : new ReLU();

    this.registerModule('self_attn', this.selfAttn);
    this.registerModule('multihead_attn', this.multiheadAttn);
    this.registerModule('linear1', this.linear1);
    this.registerModule('linear2', this.linear2);
    this.registerModule('norm1', this.norm1);
    this.registerModule('norm2', this.norm2);
    this.registerModule('norm3', this.norm3);
    this.registerModule('dropout', this.dropoutLayer);
    this.registerModule('activation', this.activation);
  }

  forward(
    tgt: Tensor,
    memory: Tensor,
    options: {
      tgtMask?: Tensor;
      memoryMask?: Tensor;
      tgtKeyPaddingMask?: Tensor;
      memoryKeyPaddingMask?: Tensor;
    } = {}
  ): Tensor {
    // Self-attention
    let attnOutput = this.selfAttn.forward(tgt, tgt, tgt, {
      attnMask: options.tgtMask,
      keyPaddingMask: options.tgtKeyPaddingMask,
    });
    attnOutput = this.dropoutLayer.forward(attnOutput);
    let x = this.norm1.forward(tgt.add(attnOutput));

    // Cross-attention
    attnOutput = this.multiheadAttn.forward(x, memory, memory, {
      attnMask: options.memoryMask,
      keyPaddingMask: options.memoryKeyPaddingMask,
    });
    attnOutput = this.dropoutLayer.forward(attnOutput);
    x = this.norm2.forward(x.add(attnOutput));

    // Feedforward
    let ffOutput = this.linear1.forward(x);
    ffOutput = this.activation.forward(ffOutput);
    ffOutput = this.dropoutLayer.forward(ffOutput);
    ffOutput = this.linear2.forward(ffOutput);
    ffOutput = this.dropoutLayer.forward(ffOutput);

    x = this.norm3.forward(x.add(ffOutput));

    return x;
  }

  extraRepr(): string {
    return `d_model=${this.dModel}, nhead=${this.nHead}, dim_feedforward=${this.dimFeedforward}, dropout=${this.dropout}`;
  }
}
