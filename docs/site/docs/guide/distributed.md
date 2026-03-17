# Distributed Training

Aethelred supports distributed training across multiple GPUs, nodes, and even TEE enclaves. The SDK provides several parallelism strategies that can be combined to scale training from a single GPU to thousands.

## Parallelism Strategies

| Strategy | What It Distributes | Communication | Best For |
|---|---|---|---|
| **DDP** (Data Parallel) | Input data batches | AllReduce gradients | Models that fit in one GPU |
| **ZeRO Stage 1** | Optimizer states | Gather on demand | Moderate memory savings |
| **ZeRO Stage 2** | Optimizer + gradients | Gather on demand | Large-batch training |
| **ZeRO Stage 3** | Optimizer + gradients + parameters | Gather on demand | Models larger than one GPU |
| **Tensor Parallel** | Individual layer computation | AllReduce activations | Large transformer layers |
| **Pipeline Parallel** | Model layers across stages | Point-to-point activations | Very deep models |

## Data-Distributed Parallel (DDP)

DDP replicates the full model on each GPU and splits input batches. Gradients are synchronized via AllReduce after each backward pass.

### Go

```go
import "github.com/aethelred/sdk-go/distributed"

dist, err := distributed.Init(distributed.Config{
    Backend:  distributed.NCCL,
    WorldSize: 4,
    Rank:     rank,  // from environment
    MasterAddr: "10.0.0.1:29500",
})
defer dist.Destroy()

model := NewClassifier(784, 256, 10)
ddpModel := distributed.NewDDP(model, dist)
optimizer := nn.NewAdamW(ddpModel.Parameters(), &nn.AdamWConfig{LR: 3e-4})

for epoch := 0; epoch < 100; epoch++ {
    sampler := distributed.NewDistributedSampler(dataset, dist)
    loader := data.NewLoader(dataset, data.WithSampler(sampler), data.WithBatchSize(64))

    for batch := range loader.Iter() {
        optimizer.ZeroGrad()
        logits := ddpModel.Forward(batch.Inputs)
        loss := nn.CrossEntropyLoss(logits, batch.Labels)
        loss.Backward()
        optimizer.Step()
    }
}
```

### Rust

```rust
use aethelred::distributed::{self, Backend, DDP};

let dist = distributed::init(Backend::Nccl, world_size, rank)?;
let model = Classifier::new(784, 256, 10);
let ddp_model = DDP::new(model, &dist)?;

for epoch in 0..100 {
    let sampler = distributed::DistributedSampler::new(&dataset, &dist);
    let loader = DataLoader::new(&dataset, 64, Some(sampler));

    for batch in loader.iter() {
        ddp_model.zero_grad();
        let logits = ddp_model.forward(&batch.inputs);
        let loss = nn::cross_entropy_loss(&logits, &batch.labels);
        loss.backward()?;
        ddp_model.step()?;
    }
}
```

## ZeRO Optimization

ZeRO (Zero Redundancy Optimizer) partitions optimizer states, gradients, and optionally parameters across devices to reduce per-GPU memory usage.

```go
model := NewLargeTransformer(config)

zeroModel := distributed.NewZeRO(model, dist, distributed.ZeROConfig{
    Stage:              3,          // partition everything
    ReduceBucketSize:   25_000_000, // 25M parameters per bucket
    OverlapComm:        true,       // overlap communication with computation
    CPUOffload:         false,      // keep on GPU
})

optimizer := nn.NewAdamW(zeroModel.Parameters(), &nn.AdamWConfig{LR: 1e-4})
```

### Memory Savings

| Configuration | 7B Model Memory per GPU (8 GPUs) |
|---|---|
| No parallelism | OOM |
| DDP | OOM |
| ZeRO Stage 1 | ~28 GB |
| ZeRO Stage 2 | ~16 GB |
| ZeRO Stage 3 | ~8 GB |
| ZeRO Stage 3 + CPU Offload | ~4 GB |

## Tensor Parallelism

Tensor parallelism splits individual layers (typically the large linear projections in transformers) across multiple GPUs.

```go
tpGroup := distributed.NewProcessGroup(dist, []int{0, 1, 2, 3})

model := NewTransformer(TransformerConfig{
    HiddenDim:  4096,
    NumHeads:   32,
    NumLayers:  32,
    TensorParallel: &distributed.TensorParallelConfig{
        Group:           tpGroup,
        ParallelLinear:  true,
        ParallelAttention: true,
    },
})
```

## Pipeline Parallelism

Pipeline parallelism assigns different layers to different GPUs and uses micro-batching to keep all stages busy.

```go
ppConfig := distributed.PipelineConfig{
    NumStages:     4,
    NumMicrobatches: 8,
    Schedule:      distributed.Schedule1F1B,  // 1-forward-1-backward
}

stages := distributed.PartitionModel(model, ppConfig, dist)
pipeline := distributed.NewPipeline(stages, ppConfig)

// Training with pipeline
loss := pipeline.TrainBatch(inputBatch, targetBatch)
```

### Schedule Comparison

| Schedule | Bubble Ratio | Memory | Implementation Complexity |
|---|---|---|---|
| GPipe | High (~50%) | High (stores all micro-batch activations) | Simple |
| 1F1B | Low (~1/stages) | Moderate | Moderate |
| Interleaved 1F1B | Lowest | Moderate | Complex |

## Mesh Topologies

For combining multiple parallelism strategies, Aethelred uses a device mesh abstraction:

```go
// 16 GPUs arranged as [4 tensor-parallel, 2 pipeline-parallel, 2 data-parallel]
mesh := distributed.NewDeviceMesh(dist, []int{4, 2, 2},
    []string{"tensor", "pipeline", "data"})

config := distributed.MeshParallelConfig{
    Mesh:            mesh,
    TensorParallel:  distributed.TP{Dim: "tensor"},
    PipelineParallel: distributed.PP{Dim: "pipeline", NumMicrobatches: 4},
    DataParallel:    distributed.DP{Dim: "data", ZeROStage: 1},
}

parallelModel := distributed.WrapMesh(model, config)
```

## Communication Backends

| Backend | Transport | GPU Support | Best For |
|---|---|---|---|
| NCCL | PCIe / NVLink / IB | NVIDIA | Multi-GPU training |
| RCCL | PCIe / IF | AMD | ROCm multi-GPU |
| Gloo | TCP / shared memory | CPU | CPU-only or mixed |
| MPI | Varies | Both | HPC clusters |

## Launching Distributed Jobs

```bash
# Local multi-GPU
aethelred launch --nproc-per-node 4 train.py

# Multi-node
aethelred launch \
  --nnodes 4 \
  --nproc-per-node 8 \
  --master-addr 10.0.0.1 \
  --master-port 29500 \
  train.py
```

## Related Pages

- [Runtime & Devices](/guide/runtime) -- device management
- [Neural Networks](/guide/neural-networks) -- model definition
- [Submitting Jobs](/guide/jobs) -- run distributed training on the Aethelred network
- [Validators](/guide/validators) -- validators execute distributed workloads
