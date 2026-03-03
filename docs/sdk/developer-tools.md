# Aethelred Developer Tools Suite

This guide covers the local-first developer tooling stack for Aethelred protocol and SDK integration work.

## Tooling Components

### 1. `aeth` CLI (Developer Operations)

Location: `$AETHELRED_REPO_ROOT/cli/aeth`

Key capabilities:

- Network status and RPC latency diagnostics
- Validator list and validator stats queries
- Offline seal verification (network fetch or local export)
- Token balance lookup + unsigned token transfer manifest generation
- Local testnet orchestration (`up`, `down`, `status`, `logs`)
- Doctor diagnostics across RPC, sample apps, and dashboard

Examples:

```bash
aeth status --network local
aeth diagnostics doctor --network local
aeth validator list --network local
aeth seal verify-file ./examples/seal-export.json
aeth wallet balance aeth1developer --network local
aeth wallet send --from aeth1from --to aeth1to --amount 1000000uaeth --out tx-send.json
aeth local up --build
```

### 2. `seal-verifier` (Standalone Offline Verification)

Location: `$AETHELRED_REPO_ROOT/cli/seal-verifier`

Modes:

- `npm` package / CLI (`seal-verifier`)
- Binary packaging script (`npm run build:bin`)
- Browser extension (`browser-extension/`, Manifest V3)

Key capabilities:

- Offline verification of exported seal JSON payloads
- Network fetch + offline verification (`verify <seal_id>`)
- Batch verification (JSON array or NDJSON)
- Audit report generation (Markdown or JSON)
- Strict mode (warnings fail CI)
- TEE freshness checks and consensus threshold checks

Examples:

```bash
seal-verifier verify-file ./seal.json --strict
seal-verifier verify seal_123 --network local --json
seal-verifier batch-verify ./seals.ndjson --json
cat ./seal.json | seal-verifier verify-stdin
seal-verifier audit ./seal.json -o ./reports/seal-audit.md
```

### 3. VS Code Extension (`aethelred-vscode`)

Location: `$AETHELRED_REPO_ROOT/vscode-extension`

Key capabilities:

- Syntax highlighting + snippets
- Inline seal verification in the current editor
- Diagnostics panel errors/warnings for invalid seal JSON
- Local testnet launcher command
- Developer dashboard launcher command
- JSON completion suggestions for seal fields

Recommended commands:

- `Aethelred: Verify Seal In Editor`
- `Aethelred: Start Local Testnet`
- `Aethelred: Open Developer Dashboard`

### 4. Local Testnet (Docker-Based)

Compose file: `$AETHELRED_REPO_ROOT/deploy/docker/docker-compose.local-testnet.yml`

Included services:

- `aethelred-mock-rpc` (deterministic mock RPC / Cosmos endpoints)
- `aethelred-fastapi-verifier` (Python FastAPI integration sample)
- `aethelred-nextjs-verifier` (Next.js API integration sample)
- `aethelred-dashboard-devtools` (developer monitoring UI on `:3101`)

Utility script:

```bash
./scripts/devtools-local-testnet.sh up
./scripts/devtools-local-testnet.sh doctor
./scripts/devtools-local-testnet.sh logs
```

Switch to the real validator-backed profile:

```bash
AETHELRED_LOCAL_TESTNET_PROFILE=real-node ./scripts/devtools-local-testnet.sh up
# or
aeth local up --profile real-node
```

### 5. `model-registry` CLI (Local-First Model Registry Workflow)

Location: `$AETHELRED_REPO_ROOT/cli/model-registry`

Key capabilities:

- Register model metadata in local registry DB
- Hash model artifacts (SHA-256)
- Verify local file against registry entry
- Update metadata/tags/owner/storage URI
- Export/import registry snapshots
- Deterministic zkML conversion plan generation

Examples:

```bash
model-registry register --name fraud-detector --file ./fraud.onnx --category financial --tag prod pii-safe
model-registry list
model-registry verify 0x... --file ./fraud.onnx
model-registry export -o ./registry-backup.json
```

### 6. Developer Dashboard (`/devtools`)

Location: `$AETHELRED_REPO_ROOT/dashboard/src/pages/devtools.tsx`

Purpose:

- Live service-health matrix for local developer stack
- Sample inference and seal route health checks
- RPC heartbeat + latency visibility
- Actionable dev workflow checklist

URL (local testnet stack):

- [http://127.0.0.1:3101/devtools](http://127.0.0.1:3101/devtools)

## Shared Verification Core

The offline seal verification logic is centralized in the TypeScript SDK and reused by developer tools:

- `$AETHELRED_REPO_ROOT/sdk/typescript/src/devtools/seal-verifier.ts`
- package export: `@aethelred/sdk/devtools`

This reduces verifier drift across:

- CLI verification
- editor diagnostics
- future browser tooling
- CI verification scripts

## Recommended CI Usage

Use strict seal verification in integration pipelines:

```bash
seal-verifier verify-file artifacts/latest-seal.json --strict --require-tee-nonce
```

Use the local testnet stack in developer smoke tests:

```bash
aeth local up --build
aeth diagnostics doctor --network local
```
