# Python SDK API Reference

## Package `aethelred-sdk`

The official Python SDK for the Aethelred AI Blockchain. Provides both synchronous and asynchronous clients, digital seals, compute jobs, neural networks, and interop with NumPy, PyTorch, and TensorFlow.

### Installation

```bash
pip install aethelred-sdk

# With ML framework integrations
pip install aethelred-sdk[ml]

# With FastAPI / LangChain integrations
pip install aethelred-sdk[integrations]

# Everything
pip install aethelred-sdk[all]
```

Requires Python >= 3.9.

### Quick Start

```python
import aethelred as aethel

# Synchronous client
with aethel.AethelredClient("https://rpc.testnet.aethelred.io") as client:
    healthy = client.health_check()

    # Submit a compute job
    job = client.jobs.submit(model_id="model-abc123", input_hash="sha256:...")

    # Create a digital seal
    seal = client.seals.create(
        job_id=job.job_id,
        purpose="credit-scoring",
        compliance_frameworks=["FCRA"],
    )

    # Verify
    result = client.verification.verify_seal(seal.id)
    print(result.valid)  # True
```

### Async Client

```python
import asyncio
import aethelred as aethel

async def main():
    async with aethel.AsyncAethelredClient(
        network=aethel.Network.TESTNET,
        api_key="your-key",
    ) as client:
        info = await client.get_node_info()
        block = await client.get_latest_block()
        print(f"Chain: {info.network}, height: {block.height}")

asyncio.run(main())
```

### Configuration

```python
from aethelred import Config, Network

config = Config(
    rpc_url="https://rpc.testnet.aethelred.io",
    api_key="your-key",
    max_connections=20,
    log_level="INFO",
)
client = aethel.AethelredClient(config)
```

| Network | Endpoint |
|---------|----------|
| `Network.MAINNET` | `https://rpc.mainnet.aethelred.io` |
| `Network.TESTNET` | `https://rpc.testnet.aethelred.io` |
| `Network.DEVNET`  | `https://rpc.devnet.aethelred.io`  |
| `Network.LOCAL`   | `http://127.0.0.1:26657`           |

### Client Modules

| Module | Access | Description |
|--------|--------|-------------|
| Jobs | `client.jobs` | Submit and track compute jobs |
| Seals | `client.seals` | Create and query digital seals |
| Models | `client.models` | Register and manage AI models |
| Validators | `client.validators` | Query validator set and hardware |
| Verification | `client.verification` | Verify seals, TEE, and zkML proofs |

---

## NumPy and PyTorch Interop

```python
import numpy as np
import aethelred as aethel

# NumPy -> Tensor
arr = np.random.randn(128, 64).astype(np.float32)
t = aethel.Tensor.from_numpy(arr)

# Tensor -> NumPy
out = t.matmul(t.t()).numpy()

# PyTorch round-trip (requires aethelred-sdk[ml])
import torch
pt = torch.randn(128, 64)
t2 = aethel.Tensor.from_torch(pt)
pt2 = t2.to_torch()
```

---

## Neural Network API

The `nn` module mirrors the PyTorch API:

```python
import aethelred as aethel
from aethelred import nn, optim

model = nn.Sequential(
    nn.Linear(784, 256),
    nn.ReLU(),
    nn.Dropout(0.2),
    nn.Linear(256, 10),
)

loss_fn = nn.CrossEntropyLoss()
optimizer = optim.AdamW(model.parameters(), lr=1e-3)

for inputs, targets in dataloader:
    output = model(inputs)
    loss = loss_fn(output, targets)
    optimizer.zero_grad()
    loss.backward()
    optimizer.step()
```

---

## Key Types

| Type | Description |
|------|-------------|
| `DigitalSeal` | Blockchain-anchored proof of AI computation |
| `ComputeJob` | Submitted AI workload with status tracking |
| `TEEAttestation` | Hardware enclave attestation record |
| `ZKMLProof` | Zero-knowledge proof for ML inference |
| `VerificationResult` | Result of seal or proof verification |
| `Tensor` | Multi-dimensional array with lazy evaluation |
| `DType` | Data type enum (`float32`, `float16`, `int8`, ...) |

---

## Error Handling

All SDK exceptions inherit from `AethelredError`:

```python
from aethelred import AethelredError, RateLimitError, ConnectionError

try:
    seal = client.seals.get("seal-id")
except RateLimitError as e:
    print(f"Retry after {e.retry_after}s")
except ConnectionError:
    print("Node unreachable")
except AethelredError as e:
    print(f"SDK error: {e}")
```

| Exception | Condition |
|-----------|-----------|
| `ConnectionError` | Node unreachable |
| `TimeoutError` | Request timed out |
| `RateLimitError` | 429 rate limit hit |
| `ValidationError` | Invalid request parameters |
| `SealError` | Seal creation/query failure |
| `JobError` | Compute job failure |
| `AuthenticationError` | Invalid or missing API key |

---

## Framework Integrations

| Integration | Install Extra | Description |
|-------------|---------------|-------------|
| PyTorch | `ml` | Tensor interop, model conversion |
| TensorFlow | `ml` | Tensor interop, SavedModel import |
| HuggingFace | `integrations` | Transformers pipeline sealing |
| FastAPI | `integrations` | Middleware for seal verification |
| LangChain | `integrations` | Chain callbacks with audit seals |

---

## See Also

- [Go SDK](/api/go/) -- Go SDK API reference
- [TypeScript SDK](/api/typescript/) -- TypeScript SDK API reference
- [TypeScript Tensor API](/api/typescript/tensor) -- Tensor operations reference
