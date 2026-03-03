# SDK Framework Integrations (Verification-First)

This document tracks the **native integration surfaces** for application frameworks and runtimes that need to emit Aethelred verification envelopes, response headers, and auditable transcripts.

## Current Native Integrations

| Surface | Status | Location | Notes |
|---|---|---|---|
| PyTorch (model wrapper) | Implemented | `sdk/python/aethelred/integrations/pytorch.py` | Wraps `torch.nn.Module`-style callables and emits envelopes on `forward` / `__call__` |
| TensorFlow / Keras Callback | Implemented | `sdk/python/aethelred/integrations/tensorflow.py` | `AethelredKerasCallback` + `create_keras_callback()` factory |
| HuggingFace Transformers | Implemented | `sdk/python/aethelred/integrations/huggingface.py` | Pipeline wrapper for prompt/output hashing and metadata |
| LangChain Runnable / Chain | Implemented | `sdk/python/aethelred/integrations/langchain.py` | `invoke`, `ainvoke`, `batch`, `abatch` |
| FastAPI Middleware (ASGI) | Implemented | `sdk/python/aethelred/integrations/fastapi.py` | Emits verification headers and records request/response envelopes |
| Next.js API Routes (Pages Router) | Implemented | `sdk/typescript/src/integrations/nextjs.ts` | `withAethelredApiRoute()` |
| Next.js App Router Route Handlers | Implemented | `sdk/typescript/src/integrations/nextjs.ts` | `withAethelredRouteHandler()` |
| Docker Official Images (templates) | Implemented | `deploy/docker/` | FastAPI verifier + Next.js API image templates |
| Kubernetes Helm Chart | Implemented | `deploy/helm/aethelred-verification-gateway/` | FastAPI/Next.js deploy chart with optional verifier sidecar |

## Verification Envelope Contract (Cross-Framework)

All native integrations emit a consistent envelope shape:

- `trace_id` / `traceId`
- `framework`
- `operation`
- `input_hash`
- `output_hash`
- `timestamp_ms`
- `metadata`

This is the minimal substrate required for:

- on-chain seal creation pipelines
- off-chain audit indexing
- institutional API observability
- deterministic replay diagnostics

## Python Example (PyTorch / FastAPI / LangChain / HF / Keras)

See:

- `sdk/python/examples/framework_integrations.py`
- `sdk/python/aethelred/integrations/__init__.py`

Install optional integrations:

```bash
pip install -e $AETHELRED_REPO_ROOT/sdk/python[integrations]
```

## TypeScript Example (Next.js)

See:

- `sdk/typescript/examples/nextjs-api-verification.ts`
- `sdk/typescript/src/integrations/nextjs.ts`

Subpath import:

```ts
import { withAethelredApiRoute, withAethelredRouteHandler } from "@aethelred/sdk/integrations";
```

## Docker + Helm Delivery Path

### Docker

- `deploy/docker/Dockerfile.fastapi-verifier`
- `deploy/docker/Dockerfile.nextjs-api`
- `deploy/docker/docker-compose.verification-stack.yml`
- Sample apps:
  - `apps/fastapi-verifier`
  - `apps/nextjs-verifier`

### Helm

- `deploy/helm/aethelred-verification-gateway/values/fastapi.yaml`
- `deploy/helm/aethelred-verification-gateway/values/nextjs.yaml`

## Go / Rust SDK Integration Strategy (Current)

The listed framework-native plugins are Python/TypeScript-first because those ecosystems own the dominant AI application surfaces today. Go and Rust SDKs still need first-class **service integration patterns** for production adoption:

- Go: `net/http` middleware / gRPC interceptors / worker instrumentation
- Rust: `tower::Layer` / `axum` middleware / `tonic` interceptors

These are documented as parity targets in the Go/Rust SDK READMEs and should follow the same envelope contract above.

## SDK CI Coverage Workflows

- TypeScript: `.github/workflows/sdk-typescript-tests.yml`
- Go: `.github/workflows/sdk-go-tests.yml`
- Go `pkg/nn` focused: `.github/workflows/sdk-go-nn-coverage.yml`
- Python: `.github/workflows/sdk-python-tests.yml`
- Rust: `.github/workflows/sdk-rust-tests.yml`
