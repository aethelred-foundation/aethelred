# Aethelred Developer Quickstart

Get started with Aethelred in under 5 minutes.

If you are onboarding a validator for the public testnet, use [TESTNET_VALIDATOR_RUNBOOK.md](./TESTNET_VALIDATOR_RUNBOOK.md). This quickstart is for developers building against the protocol and for teams validating the local developer toolchain.

## Prerequisites

- Python 3.9+ or Node.js 18+ or Go 1.21+ or Rust 1.70+
- Docker (for local development)

## 1. Choose Your SDK

Note: package registries are not published yet; commands below use source-path installs.

### Python

```bash
pip install -e sdk/python
```

```python
from aethelred import AethelredClient, ProofType

# Connect to testnet
client = AethelredClient("https://rpc.testnet.aethelred.io")

# Check network status
info = client.network.get_info()
print(f"Network: {info.network}")
print(f"Latest block: {info.latest_block_height}")
```

### TypeScript/JavaScript

```bash
npm install sdk/typescript
```

```typescript
import { AethelredClient, Network } from '@aethelred/sdk';

// Connect to testnet
const client = new AethelredClient({ network: Network.TESTNET });

// Check network status
const info = await client.network.getInfo();
console.log(`Network: ${info.network}`);
console.log(`Latest block: ${info.latestBlockHeight}`);
```

### Go

```bash
go mod edit -replace github.com/aethelred/sdk-go=sdk/go
go get github.com/aethelred/sdk-go@v2.0.0
```

```go
package main

import (
 "fmt"
 aethelred "github.com/aethelred/sdk-go"
)

func main() {
 client, _ := aethelred.NewClient(aethelred.Testnet)
 info, _ := client.Network.GetInfo(context.Background())
 fmt.Printf("Network: %s\n", info.Network)
}
```

### Rust

```toml
[dependencies]
aethelred-sdk = { path = "sdk/rust" }
```

```rust
use aethelred_sdk::{AethelredClient, Network};

#[tokio::main]
async fn main() {
 let client = AethelredClient::new(Network::Testnet).unwrap();
 let info = client.network().get_info().await.unwrap();
 println!("Network: {}", info.network);
}
```

## 2. Submit Your First Job

A "job" is a request to run AI inference with verification.

### Python Example

```python
from aethelred import AethelredClient, SubmitJobRequest, ProofType
from aethelred.utils import sha256

# Connect with wallet
client = AethelredClient(
 "https://rpc.testnet.aethelred.io",
 wallet_path="./wallet.json"
)

# Prepare model and input hashes
model_hash = sha256(open("model.onnx", "rb").read())
input_hash = sha256(b'{"age": 35, "income": 75000}')

# Submit job
response = client.jobs.submit(SubmitJobRequest(
 model_hash=model_hash,
 input_hash=input_hash,
 proof_type=ProofType.TEE,
 priority=5
))

print(f"Job ID: {response.job_id}")
print(f"Transaction: {response.tx_hash}")

# Wait for result
result = client.jobs.wait_for_completion(response.job_id, timeout=300)
print(f"Output: {result.output_hash.hex()}")
print(f"Verified: {result.verified}")
```

## 3. Create a Digital Seal

A "seal" is cryptographic proof that an AI computation was verified.

```python
from aethelred import CreateSealRequest, RegulatoryInfo

# Create seal for the completed job
seal_response = client.seals.create(CreateSealRequest(
 job_id=response.job_id,
 expires_in_blocks=10000,
 regulatory_info=RegulatoryInfo(
 jurisdiction="UAE",
 compliance_frameworks=["SOC2", "GDPR"],
 data_classification="confidential"
 )
))

print(f"Seal ID: {seal_response.seal_id}")

# Verify the seal
verification = client.seals.verify(seal_response.seal_id)
print(f"Valid: {verification.valid}")
print(f"Validators: {len(verification.seal.validators)}")
```

## 4. Local Development Setup

Run the supported local devtools stack for protocol and SDK work:

```bash
# Clone the repository
git clone https://github.com/aethelred-foundation/aethelred.git
cd aethelred

# Start the local stack (default profile: mock RPC + verifier apps)
make local-testnet-up

# Check service health
make local-testnet-doctor

# Optional: run a real local validator instead of the mock RPC profile
AETHELRED_LOCAL_TESTNET_PROFILE=real-node make local-testnet-up
```

Services available:
- **Node RPC**: http://localhost:26657
- **FastAPI verifier**: http://localhost:8000/health
- **Next.js verifier**: http://localhost:3000/api/health
- **Devtools dashboard**: http://localhost:3101/devtools (when the `dashboard` profile is enabled)

The default local stack is for developer integration and UI verification. It is not the same thing as public testnet validator onboarding.

## 5. CLI Tools

### Install CLI

```bash
cargo install aethelred-cli
```

### Configure

```bash
# Initialize config for testnet
aethelred init --network testnet

# Check connectivity
aethelred status --json

# Generate or import a key if needed
aethelred key generate
```

### Common CLI Checks

```bash
# Inspect validator/network state
aethelred validator list
aethelred validator status

# Create and verify a seal
aethelred seal create --model <HASH> --input <HASH> --output <HASH>
aethelred seal verify <SEAL_ID>
```

For the full command surface, use [docs/site/docs/cli/commands.md](./site/docs/cli/commands.md) in the repo or the live CLI docs on `docs.aethelred.io`.

## 6. VS Code Extension

1. Install "Aethelred" extension from VS Code marketplace
2. Open Command Palette (Ctrl+Shift+P)
3. Type "Aethelred: Connect to Network"
4. Select your network (Testnet)

Features:
- Sidebar with jobs, seals, validators
- Code snippets for all SDKs
- Network status in status bar

## 7. Common Patterns

### Waiting for Job Completion

```python
# With timeout and polling
result = client.jobs.wait_for_completion(
 job_id,
 timeout=300, # 5 minutes
 poll_interval=2 # Check every 2 seconds
)
```

### Batch Operations

```python
import asyncio
from aethelred import AsyncAethelredClient

async def process_batch():
 async with AsyncAethelredClient(url) as client:
 # Submit multiple jobs concurrently
 tasks = [
 client.jobs.submit(job)
 for job in job_requests
 ]
 responses = await asyncio.gather(*tasks)
 return responses
```

### Error Handling

```python
from aethelred import JobError, SealError, TimeoutError

try:
 result = client.jobs.wait_for_completion(job_id)
except TimeoutError:
 print("Job took too long")
 client.jobs.cancel(job_id)
except JobError as e:
 print(f"Job failed: {e.message}")
```

## 8. Next Steps

- Read the [full SDK documentation](./SDK_GUIDE.md)
- Learn about [post-quantum cryptography](./PQC_GUIDE.md)
- Explore [compliance features](./COMPLIANCE.md)
- Run the [example applications](../examples/)
- Follow the [testnet validator runbook](./TESTNET_VALIDATOR_RUNBOOK.md) if you are joining as an operator
- Join [Discord](https://discord.gg/aethelred) for support

## Resources

| Resource | URL |
|----------|-----|
| Documentation | https://docs.aethelred.io |
| API Reference | ./API_REFERENCE.md |
| GitHub | https://github.com/aethelred-foundation/aethelred |
| Testnet Faucet | https://faucet.testnet.aethelred.io |
| Testnet Explorer | https://explorer.testnet.aethelred.io |
| Validator Runbook | ./TESTNET_VALIDATOR_RUNBOOK.md |
