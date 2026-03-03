# `seal-verifier`

Standalone Aethelred Digital Seal verification tool.

Supports:

- offline seal verification from local JSON export
- network fetch + offline verification
- batch verification (JSON array / NDJSON)
- audit report generation
- strict mode for CI
- browser extension (see `browser-extension/`)

## Usage

```bash
seal-verifier verify-file ./seal.json --strict
seal-verifier verify seal_123 --network local --json
seal-verifier audit ./seal.json -o ./reports/seal-audit.md
```

## Build

```bash
npm install
npm run build
```

## Binary Packaging

```bash
npm run build:bin
```

