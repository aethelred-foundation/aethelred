# Aethelred SDK & Tools Guide

Comprehensive documentation for the Aethelred SDK ecosystem, covering all supported languages, CLI tools, and developer resources.

## Table of Contents

1. [Overview](#overview)
2. [Quick Start](#quick-start)
3. [Python SDK](#python-sdk)
4. [TypeScript SDK](#typescript-sdk)
5. [Rust SDK](#rust-sdk)
6. [Go SDK](#go-sdk)
7. [CLI Tools](#cli-tools)
8. [Docker Development](#docker-development)
9. [VS Code Extension](#vs-code-extension)
10. [Dashboard](#dashboard)
11. [API Reference](#api-reference)

---

## Overview

The Aethelred SDK ecosystem provides comprehensive tools for interacting with the Aethelred AI Blockchain. All SDKs follow consistent design patterns and provide:

- **Full API Coverage**: Jobs, Seals, Models, Validators, Verification
- **Async/Sync Support**: Choose the programming model that fits your use case
- **Type Safety**: Full type definitions for IDE support and compile-time checks
- **Post-Quantum Cryptography**: Dilithium signatures and Kyber key exchange
- **Compliance Built-in**: HIPAA, GDPR, SOC2, CCPA support

### Supported Networks

| Network | RPC URL | Chain ID |
|---------|---------|----------|
| Mainnet | `https://rpc.mainnet.aethelred.org` | `aethelred-1` |
| Testnet | `https://rpc.testnet.aethelred.org` | `aethelred-testnet-1` |
| Devnet | `https://rpc.devnet.aethelred.org` | `aethelred-devnet-1` |
| Local | `http://localhost:26657` | `aethelred-local` |

---

## Quick Start

### Installation

```bash
# Python
pip install -e sdk/python

# TypeScript/JavaScript
npm install sdk/typescript

# Rust (Cargo.toml)
# aethelred-sdk = { path = "sdk/rust" }

# Go
go mod edit -replace github.com/aethelred/sdk-go=sdk/go
go get github.com/aethelred/sdk-go@v2.0.0
```

Public registry installs are enabled after package publishing.

### First Request

```python
# Python
from aethelred import AethelredClient

client = AethelredClient("https://rpc.testnet.aethelred.org")
stats = client.network.get_stats()
print(f"Active validators: {stats.active_validators}")
```

```typescript
// TypeScript
import { AethelredClient } from '@aethelred/sdk';

const client = new AethelredClient({
  rpcUrl: 'https://rpc.testnet.aethelred.org'
});
const stats = await client.network.getStats();
console.log(`Active validators: ${stats.activeValidators}`);
```

---

## Python SDK

### Installation

```bash
pip install -e sdk/python

# With ML dependencies
pip install -e sdk/python[ml]

# With post-quantum crypto
pip install -e sdk/python[pqc]

# Everything
pip install -e sdk/python[all]
```

### Configuration

```python
from aethelred import AethelredClient, Config, Network

# Simple connection
client = AethelredClient("https://rpc.testnet.aethelred.org")

# With configuration
config = Config(
    network=Network.TESTNET,
    timeout=30.0,
    max_retries=3,
    api_key="your-api-key"  # Optional
)
client = AethelredClient.from_config(config)
```

### Jobs Module

```python
from aethelred import SubmitJobRequest, ProofType

# Submit a compute job
request = SubmitJobRequest(
    model_hash=b"...",
    input_hash=b"...",
    proof_type=ProofType.TEE,
    priority=5,
    timeout_blocks=100
)
response = client.jobs.submit(request)
print(f"Job submitted: {response.job_id}")

# Wait for completion
result = client.jobs.wait_for_completion(response.job_id, timeout=300)
print(f"Output hash: {result.output_hash.hex()}")

# List jobs
jobs = client.jobs.list(status="pending", limit=10)
for job in jobs:
    print(f"Job {job.id}: {job.status}")
```

### Seals Module

```python
from aethelred import CreateSealRequest, RegulatoryInfo

# Create a seal
request = CreateSealRequest(
    job_id="job_abc123",
    expires_in_blocks=1000,
    regulatory_info=RegulatoryInfo(
        jurisdiction="UAE",
        compliance_frameworks=["SOC2"],
        data_classification="confidential"
    )
)
response = client.seals.create(request)
print(f"Seal created: {response.seal_id}")

# Verify a seal
verification = client.seals.verify("seal_xyz789")
print(f"Valid: {verification.valid}")
print(f"Verification details: {verification.verification_details}")
```

### Async Client

```python
import asyncio
from aethelred import AsyncAethelredClient

async def main():
    async with AsyncAethelredClient("https://rpc.testnet.aethelred.org") as client:
        # Concurrent operations
        jobs, seals = await asyncio.gather(
            client.jobs.list(limit=10),
            client.seals.list(limit=10)
        )
        print(f"Found {len(jobs)} jobs and {len(seals)} seals")

asyncio.run(main())
```

### Post-Quantum Cryptography

```python
from aethelred.crypto import DilithiumSigner, DilithiumSecurityLevel

# Generate Dilithium keypair
signer = DilithiumSigner(DilithiumSecurityLevel.LEVEL3)
keypair = signer.generate_keypair()

# Sign a message
message = b"Hello, Aethelred!"
signature = signer.sign(message, keypair.private_key)

# Verify
is_valid = signer.verify(message, signature, keypair.public_key)
print(f"Signature valid: {is_valid}")
```

### Compliance

```python
from aethelred.compliance import PIIScrubber, ComplianceChecker

# Scrub PII from data
scrubber = PIIScrubber()
clean_data = scrubber.scrub("Call me at 555-123-4567")
print(clean_data)  # "Call me at [PHONE]"

# Check compliance
checker = ComplianceChecker(frameworks=["HIPAA", "GDPR"])
result = checker.check(data)
print(f"Compliant: {result.is_compliant}")
```

---

## TypeScript SDK

### Installation

```bash
npm install sdk/typescript
```

### Configuration

```typescript
import { AethelredClient, Network } from '@aethelred/sdk';

// Simple
const client = new AethelredClient({
  rpcUrl: 'https://rpc.testnet.aethelred.org'
});

// With options
const client = new AethelredClient({
  network: Network.TESTNET,
  timeout: 30000,
  maxRetries: 3,
  apiKey: 'your-api-key'
});
```

### Jobs Module

```typescript
import { ProofType, SubmitJobRequest } from '@aethelred/sdk';

// Submit job
const request: SubmitJobRequest = {
  modelHash: Buffer.from('...'),
  inputHash: Buffer.from('...'),
  proofType: ProofType.TEE,
  priority: 5
};
const response = await client.jobs.submit(request);

// Wait for completion
const result = await client.jobs.waitForCompletion(response.jobId, {
  timeout: 300000,
  pollInterval: 2000
});
```

### Seals Module

```typescript
// Create seal
const seal = await client.seals.create({
  jobId: 'job_abc123',
  expiresInBlocks: 1000,
  regulatoryInfo: {
    jurisdiction: 'UAE',
    complianceFrameworks: ['SOC2']
  }
});

// Verify seal
const verification = await client.seals.verify(seal.sealId);
console.log(`Valid: ${verification.valid}`);
```

### WebSocket Subscriptions

```typescript
// Subscribe to job updates
const subscription = await client.jobs.subscribe({
  status: 'pending',
  onJob: (job) => {
    console.log(`Job update: ${job.id} - ${job.status}`);
  },
  onError: (error) => {
    console.error('Subscription error:', error);
  }
});

// Cleanup
subscription.unsubscribe();
```

---

## Rust SDK

### Installation

```toml
[dependencies]
aethelred-sdk = "1.0"
tokio = { version = "1", features = ["full"] }
```

### Usage

```rust
use aethelred_sdk::{AethelredClient, Network, ProofType};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client
    let client = AethelredClient::new(Network::Testnet)?;

    // Submit job
    let job = client.jobs()
        .submit()
        .model_hash(&model_hash)
        .input_hash(&input_hash)
        .proof_type(ProofType::Tee)
        .priority(5)
        .send()
        .await?;

    println!("Job submitted: {}", job.job_id);

    // Wait for completion
    let result = client.jobs()
        .wait_for_completion(&job.job_id)
        .timeout(Duration::from_secs(300))
        .await?;

    println!("Result: {:?}", result);
    Ok(())
}
```

### Seals

```rust
// Create seal
let seal = client.seals()
    .create()
    .job_id(&job_id)
    .expires_in_blocks(1000)
    .regulatory_info(RegulatoryInfo {
        jurisdiction: "UAE".to_string(),
        compliance_frameworks: vec!["SOC2".to_string()],
        ..Default::default()
    })
    .send()
    .await?;

// Verify
let verification = client.seals().verify(&seal.seal_id).await?;
assert!(verification.valid);
```

---

## Go SDK

### Installation

```bash
go mod edit -replace github.com/aethelred/sdk-go=sdk/go
go get github.com/aethelred/sdk-go@v2.0.0
```

### Usage

```go
package main

import (
    "context"
    "fmt"
    "log"

    aethelred "github.com/aethelred/sdk-go"
)

func main() {
    // Create client
    client, err := aethelred.NewClient(aethelred.Testnet)
    if err != nil {
        log.Fatal(err)
    }

    ctx := context.Background()

    // Submit job
    resp, err := client.Jobs.Submit(ctx, aethelred.SubmitJobRequest{
        ModelHash: modelHash,
        InputHash: inputHash,
        ProofType: aethelred.ProofTypeTEE,
        Priority:  5,
    })
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Job submitted: %s\n", resp.JobID)

    // Get seal
    seal, err := client.Seals.Get(ctx, sealID)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("Seal status: %s\n", seal.Status)
}
```

---

## CLI Tools

### Aethelred CLI (`aethel`)

The main CLI for interacting with Aethelred.

```bash
# Install
npm install -g @aethelred/cli

# Configure
aethel config set-network testnet
aethel config set-wallet ./wallet.json

# Job commands
aethel job submit --model <hash> --input <hash> --proof-type tee
aethel job status <job-id>
aethel job list --status pending

# Seal commands
aethel seal create --job <job-id>
aethel seal verify <seal-id>
aethel seal export <seal-id> --format pdf

# Network info
aethel network info
aethel network stats
```

### Seal Verifier (`seal-verifier`)

Standalone tool for seal verification.

```bash
# Install
npm install -g @aethelred/seal-verifier

# Verify seal
seal-verifier verify <seal-id> --network testnet

# Verify from file
seal-verifier verify-file ./seal.json

# Export verification report
seal-verifier report <seal-id> --output verification-report.pdf
```

### Model Registry CLI (`model-registry`)

Manage AI models on the network.

```bash
# Install
npm install -g @aethelred/model-registry

# Register model
model-registry register \
  --name "Credit Scorer v1" \
  --file ./model.onnx \
  --category financial \
  --input-schema ./input.json \
  --output-schema ./output.json

# List models
model-registry list --category financial

# Get model info
model-registry info <model-hash>
```

---

## Docker Development

### Quick Start

```bash
cd docker/
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f aethelred-node
```

### Services

| Service | Port | Description |
|---------|------|-------------|
| `aethelred-node` | 26657, 26656, 1317, 9090 | Aethelred node |
| `tee-worker` | 8545 | TEE execution worker |
| `zkml-prover` | 8546 | zkML proving service |
| `explorer` | 3000 | Block explorer |
| `faucet` | 8080 | Testnet faucet |
| `prometheus` | 9092 | Metrics |
| `grafana` | 3001 | Dashboards |

### Development Workflow

```bash
# Start specific services
docker-compose up -d aethelred-node explorer

# Reset chain state
docker-compose down -v
docker-compose up -d

# Access node shell
docker-compose exec aethelred-node sh

# Query via REST
curl http://localhost:1317/aethelred/seal/v1/seals
```

---

## VS Code Extension

### Installation

1. Open VS Code
2. Go to Extensions (Ctrl+Shift+X)
3. Search for "Aethelred"
4. Click Install

### Features

- **Syntax highlighting** for Aethelred configuration files
- **Code snippets** for Python and TypeScript
- **Explorer sidebar** showing jobs, seals, and validators
- **Network status** in status bar
- **Quick commands** (Ctrl+Shift+P → "Aethelred:")

### Snippets

```typescript
// Type 'aethel-client' for:
const client = new AethelredClient({
  rpcUrl: 'https://rpc.testnet.aethelred.org'
});

// Type 'aethel-job' for:
const job = await client.jobs.submit({
  modelHash: modelHash,
  inputHash: inputHash,
  proofType: ProofType.TEE
});

// Type 'aethel-seal' for:
const seal = await client.seals.create({
  jobId: 'job_id'
});
```

---

## Dashboard

Web-based blockchain explorer and dashboard.

### Running Locally

```bash
cd dashboard/
npm install
npm run dev
```

Open http://localhost:3000

### Features

- **Network Stats**: Real-time blockchain statistics
- **Jobs Explorer**: Browse and filter compute jobs
- **Seals Viewer**: View and verify digital seals
- **Validators**: Monitor validator performance
- **Models Registry**: Browse registered AI models

### Configuration

```env
NEXT_PUBLIC_RPC_URL=https://rpc.mainnet.aethelred.org
NEXT_PUBLIC_API_URL=https://api.mainnet.aethelred.org
```

---

## API Reference

### Jobs Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/jobs` | Submit a new job |
| GET | `/v1/jobs/{id}` | Get job by ID |
| GET | `/v1/jobs` | List jobs |
| DELETE | `/v1/jobs/{id}` | Cancel a job |
| GET | `/v1/jobs/{id}/result` | Get job result |

### Seals Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/seals` | Create a seal |
| GET | `/v1/seals/{id}` | Get seal by ID |
| GET | `/v1/seals` | List seals |
| POST | `/v1/seals/{id}/verify` | Verify a seal |
| POST | `/v1/seals/{id}/revoke` | Revoke a seal |

### Models Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/models` | Register a model |
| GET | `/v1/models/{hash}` | Get model by hash |
| GET | `/v1/models` | List models |

### Validators Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/validators` | List validators |
| GET | `/v1/validators/{address}` | Get validator by address |
| GET | `/v1/validators/{address}/stats` | Get validator stats |

### Network Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/v1/network/info` | Get network info |
| GET | `/v1/network/stats` | Get network stats |
| GET | `/v1/network/epoch/{number}` | Get epoch stats |

---

## Error Handling

All SDKs use consistent error types:

```python
from aethelred import AethelredError, JobError, SealError

try:
    seal = client.seals.get("invalid_id")
except SealError as e:
    print(f"Seal error: {e.message}")
    print(f"Error code: {e.code}")
except AethelredError as e:
    print(f"General error: {e}")
```

### Error Codes

| Code | Description |
|------|-------------|
| `INVALID_REQUEST` | Invalid request parameters |
| `NOT_FOUND` | Resource not found |
| `UNAUTHORIZED` | Authentication required |
| `RATE_LIMITED` | Too many requests |
| `INTERNAL_ERROR` | Server error |
| `TIMEOUT` | Request timeout |
| `NETWORK_ERROR` | Connection error |

---

## Support

- **Documentation**: https://docs.aethelred.org
- **GitHub**: https://github.com/aethelred
- **Discord**: https://discord.gg/aethelred
- **Email**: developers@aethelred.org
