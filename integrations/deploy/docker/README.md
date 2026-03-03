# Aethelred Official Image Templates (Framework Integrations)

These Dockerfiles extend the existing node/bridge images with **application-facing verification runtimes** for AI/ML services.

## Image Templates

- `Dockerfile.node`: Core node runtime (validator / compute / bootnode)
- `Dockerfile.bridge`: Bridge relayer runtime
- `Dockerfile.fastapi-verifier`: Python FastAPI service using `aethelred.integrations.AethelredVerificationMiddleware`
- `Dockerfile.nextjs-api`: Next.js API application using `withAethelredApiRoute()` / `withAethelredRouteHandler()`

## Build Commands

```bash
docker build -f deploy/docker/Dockerfile.fastapi-verifier \
  --build-arg APP_DIR=apps/fastapi-verifier \
  -t ghcr.io/aethelred/fastapi-verifier:latest .

docker build -f deploy/docker/Dockerfile.nextjs-api \
  --build-arg APP_DIR=apps/nextjs-verifier \
  -t ghcr.io/aethelred/nextjs-api:latest .
```

## Runtime Environment Variables

- `AETHELRED_RPC_URL`: Aethelred RPC / API endpoint used by SDK clients and verification hooks
- `AETHELRED_HEADER_PREFIX`: Response header prefix for verification metadata (`x-aethelred` default)
- `AETHELRED_VERIFY_MODE`: Application mode (for example `seal-envelope`, `tee`, `hybrid`)

## Local Stack

Use `docker-compose.verification-stack.yml` as a starting template for running a FastAPI gateway, Next.js API app, and a local node endpoint together.

```bash
docker compose -f deploy/docker/docker-compose.verification-stack.yml up --build
```

### Developer Tools Local Testnet (Mock RPC + Sample Apps + Dashboard)

For end-to-end SDK integration development (including the developer dashboard), use:

```bash
docker compose -f deploy/docker/docker-compose.local-testnet.yml up --build
```

Switch RPC backend profile:

- Mock RPC (default): `--profile mock`
- Real validator node: `--profile real-node`

Examples:

```bash
docker compose -f deploy/docker/docker-compose.local-testnet.yml --profile mock up --build
docker compose -f deploy/docker/docker-compose.local-testnet.yml --profile real-node up --build
```

Services:

- Mock RPC endpoint: `http://127.0.0.1:26657`
- FastAPI verifier sample: `http://127.0.0.1:8000`
- Next.js verifier sample: `http://127.0.0.1:3000`
- Developer dashboard: `http://127.0.0.1:3101/devtools`
