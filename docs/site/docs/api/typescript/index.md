# TypeScript SDK API Reference

## Package `@aethelred/sdk`

The official TypeScript/JavaScript SDK for the Aethelred AI Blockchain. Provides blockchain client, digital seals, compute jobs, neural networks, and tensor operations with WebGPU acceleration.

### Installation

```bash
npm install @aethelred/sdk
# or
yarn add @aethelred/sdk
# or
pnpm add @aethelred/sdk
```

Requires Node.js >= 18.0.0. TypeScript >= 5.0 recommended.

### ESM and CJS Support

The SDK ships dual-format builds. Subpath exports are available for tree-shaking:

```typescript
// ESM (recommended)
import { AethelredClient } from '@aethelred/sdk';
import { SealsModule } from '@aethelred/sdk/seals';
import { JobsModule } from '@aethelred/sdk/jobs';

// CommonJS
const { AethelredClient } = require('@aethelred/sdk');
```

### Quick Start

```typescript
import { AethelredClient } from '@aethelred/sdk';

const client = new AethelredClient({
  rpcUrl: 'https://rpc.testnet.aethelred.io',
  apiKey: process.env.AETHELRED_API_KEY,
});

// Check node health
const healthy = await client.healthCheck();

// Submit a compute job
const job = await client.jobs.submit({
  modelId: 'model-abc123',
  inputHash: 'sha256:...',
});

// Create a digital seal
const seal = await client.seals.create({
  jobId: job.jobId,
  purpose: 'credit-scoring',
  complianceFrameworks: ['FCRA'],
});

// Verify a seal
const result = await client.verification.verifySeal(seal.id);
console.log(result.valid); // true
```

### Client Configuration

```typescript
interface Config {
  rpcUrl?: string;
  apiKey?: string;
  chainId?: string;
  network?: 'mainnet' | 'testnet' | 'devnet' | 'local';
  timeout?: { read: number; write: number; connect: number };
  maxRetries?: number;
}
```

| Network   | Endpoint                              |
|-----------|---------------------------------------|
| `mainnet` | `https://rpc.mainnet.aethelred.io`   |
| `testnet` | `https://rpc.testnet.aethelred.io`   |
| `devnet`  | `https://rpc.devnet.aethelred.io`    |
| `local`   | `http://localhost:26657`              |

### Client Modules

| Module         | Access                  | Description                        |
|----------------|-------------------------|------------------------------------|
| Jobs           | `client.jobs`           | Submit and track compute jobs      |
| Seals          | `client.seals`          | Create and query digital seals     |
| Models         | `client.models`         | Register and manage AI models      |
| Validators     | `client.validators`     | Query validator set and hardware   |
| Verification   | `client.verification`   | Verify seals, TEE, and zkML proofs |

### Browser vs Node.js

The SDK works in both environments. In browsers, WebGPU acceleration is available for tensor operations when supported. In Node.js, CPU backends are used by default with optional native GPU bindings.

```typescript
// Browser: WebGPU tensor acceleration
import { Tensor } from '@aethelred/sdk';
const t = Tensor.randn([512, 512], { device: 'webgpu' });

// Node.js: HTTP client, seals, jobs
import { AethelredClient } from '@aethelred/sdk';
const client = new AethelredClient('https://rpc.testnet.aethelred.io');
```

### Error Handling

All SDK errors extend `AethelredError`:

```typescript
import { AethelredError, RateLimitError, ConnectionError } from '@aethelred/sdk';

try {
  await client.seals.get('seal-id');
} catch (err) {
  if (err instanceof RateLimitError) {
    console.log(`Retry after ${err.retryAfter}s`);
  } else if (err instanceof ConnectionError) {
    console.log('Node unreachable');
  }
}
```

---

## Sub-packages

- [runtime](./runtime) -- Device management, memory pools, WebGPU backend
- [tensor](./tensor) -- Tensor operations with lazy evaluation
- [module](./module) -- Neural network modules and training utilities
- [Go SDK](/api/go/) -- Go SDK API reference
- [Python SDK](/api/python/) -- Python SDK API reference
