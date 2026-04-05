# Submitting Jobs

Compute jobs are the primary mechanism for running AI workloads on the Aethelred network. When you submit a job, validators execute it inside TEE enclaves, produce attestation quotes and optional zkML proofs, and record the results on-chain as [Digital Seals](/guide/digital-seals).

## Job Lifecycle

```
1. CREATED    ─ Job submitted to mempool
2. PENDING    ─ Included in a block, awaiting validator assignment
3. ASSIGNED   ─ Assigned to a validator set
4. RUNNING    ─ Executing inside TEE enclave(s)
5. VERIFYING  ─ Attestation quotes and proofs being verified
6. COMPLETED  ─ Results finalized on-chain
   or
   FAILED     ─ Execution error or verification failure
```

## Submitting a Job

### Go

```go
job, err := client.SubmitJob(ctx, &aethelred.JobRequest{
    Type:        aethelred.JobTypeInference,
    ModelSealID: modelSealID,             // reference to a sealed model
    Input:       inputData,               // serialized tensor or data
    Config: aethelred.JobConfig{
        MaxGas:       500_000,
        TEERequired:  true,
        ZKProof:      true,               // generate zkML proof
        ProofBackend: aethelred.ProofPLONK,
        Timeout:      5 * time.Minute,
    },
})
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Job ID:     %s\n", job.ID)
fmt.Printf("Status:     %s\n", job.Status)
fmt.Printf("TX Hash:    %s\n", job.TxHash)
```

### Rust

```rust
let job = client.submit_job(JobRequest {
    job_type: JobType::Inference,
    model_seal_id: model_seal_id,
    input: input_data,
    config: JobConfig {
        max_gas: 500_000,
        tee_required: true,
        zk_proof: true,
        proof_backend: ProofBackend::Plonk,
        timeout: Duration::from_secs(300),
    },
}).await?;

println!("Job ID: {}", job.id);
```

### TypeScript

```typescript
const job = await client.submitJob({
  type: JobType.Inference,
  modelSealId: modelSealId,
  input: inputData,
  config: {
    maxGas: 500_000,
    teeRequired: true,
    zkProof: true,
    proofBackend: ProofBackend.PLONK,
    timeout: 300_000,
  },
});

console.log(`Job ID: ${job.id}`);
```

## Job Types

| Type | Description | Typical Duration | Output |
|---|---|---|---|
| `Inference` | Run a model on input data | Seconds | Prediction tensor |
| `Training` | Train or fine-tune a model | Minutes to hours | Model checkpoint |
| `Evaluation` | Evaluate model on a test dataset | Minutes | Metrics (accuracy, loss) |
| `Quantization` | Quantize a model | Minutes | Quantized checkpoint |
| `ProofGeneration` | Generate a zkML proof for existing results | Minutes | ZK proof bytes |

## Monitoring Jobs

### Polling

```go
for {
    status, err := client.JobStatus(ctx, jobID)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Status: %s  Progress: %d%%\n", status.State, status.Progress)

    if status.State == aethelred.JobCompleted || status.State == aethelred.JobFailed {
        break
    }
    time.Sleep(5 * time.Second)
}
```

### WebSocket Subscription

```go
sub, err := client.SubscribeJobUpdates(ctx, jobID)
for update := range sub.Updates() {
    fmt.Printf("[%s] %s: %s\n", update.Timestamp, update.State, update.Message)
}
```

### CLI

```bash
aethelred job status <job-id>
aethelred job watch <job-id>   # live updates
aethelred job logs <job-id>    # execution logs (if available)
```

## Retrieving Results

```go
result, err := client.JobResult(ctx, jobID)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Output shape: %v\n", result.Output.Shape())
fmt.Printf("Seal ID:      %s\n", result.SealID)
fmt.Printf("TEE Quote:    %v\n", result.TEEQuote != nil)
fmt.Printf("ZK Proof:     %v\n", result.ZKProof != nil)
fmt.Printf("Gas used:     %d\n", result.GasUsed)
fmt.Printf("Duration:     %s\n", result.Duration)
```

## Job Pricing

Job costs depend on the compute resources consumed and the proof generation requirements:

| Component | Cost Formula |
|---|---|
| Base fee | `0.01 AETHEL` per job |
| Compute | `gas_used * gas_price` (default `0.025 uaethel/gas`) |
| TEE premium | `+20%` of compute cost for TEE execution |
| zkML proof | `proof_constraints * 0.000001 uaethel` |
| Storage | `output_size_bytes * 0.0001 uaethel` |

### Estimating Cost

```go
estimate, err := client.EstimateJobCost(ctx, &aethelred.JobRequest{
    Type:        aethelred.JobTypeInference,
    ModelSealID: modelSealID,
    Input:       inputData,
    Config:      jobConfig,
})

fmt.Printf("Estimated gas:  %d\n", estimate.Gas)
fmt.Printf("Estimated cost: %s AETHEL\n", estimate.Cost)
```

## Batch Jobs

Submit multiple jobs in a single transaction for efficiency:

```go
batch := client.NewJobBatch()
for _, input := range inputs {
    batch.Add(&aethelred.JobRequest{
        Type:        aethelred.JobTypeInference,
        ModelSealID: modelSealID,
        Input:       input,
        Config:      config,
    })
}

results, err := batch.Submit(ctx)
fmt.Printf("Submitted %d jobs\n", len(results))
```

## Cancellation

Jobs can be cancelled before they enter the `RUNNING` state:

```go
err := client.CancelJob(ctx, jobID)
```

Jobs already in `RUNNING` state will complete; gas for executed compute is still charged.

## Related Pages

- [Digital Seals](/guide/digital-seals) -- job results are recorded as seals
- [TEE Attestation](/guide/tee-attestation) -- job execution attestation
- [zkML Proofs](/guide/zkml-proofs) -- optional proof generation for jobs
- [Model Registry](/guide/model-registry) -- reference models by seal ID
- [Validators](/guide/validators) -- validators execute jobs
