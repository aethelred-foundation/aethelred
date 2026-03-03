# Aethelred Verification Gateway Helm Chart

Helm chart for deploying **application-facing AI APIs** (FastAPI or Next.js) with native Aethelred verification integrations.

## What This Chart Deploys

- Your API container (`FastAPI` or `Next.js`)
- A ConfigMap with Aethelred verification runtime settings
- Optional verification sidecar (`verification.sidecar.enabled=true`)
- Service, optional Ingress, optional HPA

## Install

FastAPI profile:

```bash
helm upgrade --install verifier-fastapi \
  deploy/helm/aethelred-verification-gateway \
  -f deploy/helm/aethelred-verification-gateway/values/fastapi.yaml
```

Next.js profile:

```bash
helm upgrade --install verifier-nextjs \
  deploy/helm/aethelred-verification-gateway \
  -f deploy/helm/aethelred-verification-gateway/values/nextjs.yaml
```

## Key Values

- `application.runtime`: `fastapi` or `nextjs`
- `application.image.*`: app image repository/tag/pullPolicy
- `verification.rpcUrl`: RPC/API endpoint for Aethelred
- `verification.headerPrefix`: response header prefix (`x-aethelred`)
- `verification.mode`: operational mode (`seal-envelope`, `tee`, `hybrid`)
- `verification.sidecar.enabled`: attach verifier proxy sidecar

## Integration Expectation

This chart assumes the application image already uses:

- Python: `aethelred.integrations.AethelredVerificationMiddleware`
- TypeScript: `withAethelredApiRoute()` / `withAethelredRouteHandler()`
